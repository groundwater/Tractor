import Foundation
import X509
import SwiftASN1
import Crypto
import os.log

private let caLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "ca")
private let appGroupID = "group.com.jacobgroundwater.Tractor"

/// Generates a self-signed CA and signs per-hostname leaf certificates on the fly.
/// The CA key + cert are persisted to the app group container so they survive
/// sysext restarts.
final class CertificateAuthority {
    let caKey: P256.Signing.PrivateKey
    let caCert: Certificate
    let caDER: [UInt8]

    /// Cache of hostname → SecIdentity
    private var cache: [String: SecIdentity] = [:]
    private let cacheLock = NSLock()

    /// Reference to the reporter for reverse XPC to CLI
    weak var reporter: FlowReporter?

    /// Load an existing CA from disk, or generate a new one if none exists.
    init() throws {
        if let loaded = try? CertificateAuthority.loadFromDisk() {
            self.caKey = loaded.key
            self.caCert = loaded.cert
            self.caDER = loaded.der
            os_log("CA loaded from disk: %d bytes DER", log: caLog, type: .default, caDER.count)
        } else {
            let key = P256.Signing.PrivateKey()

            let name = try DistinguishedName {
                CommonName("Tractor MITM CA")
                OrganizationName("Tractor")
            }

            let keyID = ArraySlice(Insecure.SHA1.hash(data: key.publicKey.derRepresentation))

            let cert = try Certificate(
                version: .v3,
                serialNumber: Certificate.SerialNumber(),
                publicKey: .init(key.publicKey),
                notValidBefore: Date() - 86400,
                notValidAfter: Date() + (3650 * 86400),
                issuer: name,
                subject: name,
                signatureAlgorithm: .ecdsaWithSHA256,
                extensions: try Certificate.Extensions {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                    Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                    SubjectKeyIdentifier(keyIdentifier: keyID)
                },
                issuerPrivateKey: .init(key)
            )

            var serializer = DER.Serializer()
            try serializer.serialize(cert)

            self.caKey = key
            self.caCert = cert
            self.caDER = serializer.serializedBytes

            try saveToDisk()
            os_log("CA generated and saved: %d bytes DER", log: caLog, type: .default, caDER.count)
        }
    }

    // MARK: - Persistence

    private static var containerURL: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
    }

    private static var certPath: URL? { containerURL?.appendingPathComponent("mitm-ca.der") }
    private static var keyPath: URL? { containerURL?.appendingPathComponent("mitm-ca.key") }

    private struct LoadedCA {
        let key: P256.Signing.PrivateKey
        let cert: Certificate
        let der: [UInt8]
    }

    private static func loadFromDisk() throws -> LoadedCA {
        guard let certURL = certPath, let keyURL = keyPath else {
            throw CocoaError(.fileNoSuchFile)
        }
        let derData = try Data(contentsOf: certURL)
        let keyData = try Data(contentsOf: keyURL)
        let key = try P256.Signing.PrivateKey(derRepresentation: keyData)
        let cert = try Certificate(derEncoded: Array(derData))
        return LoadedCA(key: key, cert: cert, der: Array(derData))
    }

    private func saveToDisk() throws {
        guard let certURL = Self.certPath, let keyURL = Self.keyPath else {
            os_log("CA: no app group container — cannot persist", log: caLog, type: .error)
            return
        }
        try Data(caDER).write(to: certURL, options: .atomic)
        try Data(caKey.derRepresentation).write(to: keyURL, options: .atomic)
        os_log("CA saved to %{public}@", log: caLog, type: .default, certURL.deletingLastPathComponent().path)
    }

    // MARK: - PEM export

    var caPEM: String {
        let base64 = Data(caDER).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN CERTIFICATE-----\n\(base64)\n-----END CERTIFICATE-----\n"
    }

    // MARK: - Leaf identity via CLI P12

    func identity(for hostname: String) throws -> SecIdentity {
        cacheLock.lock()
        if let cached = cache[hostname] {
            cacheLock.unlock()
            return cached
        }
        cacheLock.unlock()

        guard let reporter = reporter else {
            fatalError("CertificateAuthority.identity(\(hostname)): reporter is nil")
        }
        guard let p12Data = reporter.requestP12(hostname: hostname) else {
            fatalError("CertificateAuthority.identity(\(hostname)): requestP12 returned nil")
        }
        guard !p12Data.isEmpty else {
            fatalError("CertificateAuthority.identity(\(hostname)): requestP12 returned empty")
        }

        let options: [String: Any] = [kSecImportExportPassphrase as String: "tractor"]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess else {
            fatalError("CertificateAuthority.identity(\(hostname)): SecPKCS12Import failed: \(status)")
        }
        guard let array = items as? [[String: Any]], let first = array.first,
              let identity = first[kSecImportItemIdentity as String] as! SecIdentity? else {
            fatalError("CertificateAuthority.identity(\(hostname)): no identity in PKCS12 result")
        }

        os_log("leaf cert for %{public}@: imported via CLI PKCS12", log: caLog, type: .default, hostname)
        cacheLock.lock()
        cache[hostname] = identity
        cacheLock.unlock()
        return identity
    }

}
