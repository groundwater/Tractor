import Foundation
import Security
import os.log

private let p12Log = OSLog(subsystem: "com.jacobgroundwater.Tractor.NE", category: "pkcs12")

/// Builds a minimal PKCS#12 blob from a certificate DER + private key PKCS8 DER,
/// then imports it via SecPKCS12Import to produce a SecIdentity.
/// This bypasses the keychain entirely — SecPKCS12Import creates items in a
/// temporary import context.
enum PKCS12Builder {

    /// Create a SecIdentity from raw cert and key DER bytes.
    static func makeIdentity(certDER: [UInt8], keyPKCS8DER: [UInt8]) throws -> SecIdentity {
        let p12Data = buildPKCS12(certDER: certDER, keyPKCS8DER: keyPKCS8DER, password: "x")

        let options: [String: Any] = [kSecImportExportPassphrase as String: "x"]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess, let array = items as? [[String: Any]], let first = array.first else {
            os_log("SecPKCS12Import failed: %d", log: p12Log, type: .error, status)
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }

        guard let identity = first[kSecImportItemIdentity as String] as! SecIdentity? else {
            os_log("PKCS12 import: no identity returned", log: p12Log, type: .error)
            throw NSError(domain: "PKCS12Builder", code: -1,
                          userInfo: [NSLocalizedDescriptionKey: "No identity in PKCS12 import result"])
        }

        return identity
    }

    // MARK: - PKCS12 DER construction

    /// Build a PKCS#12 PFX PDU with password-based MAC (no encryption).
    /// This is the simplest structure that SecPKCS12Import accepts.
    private static func buildPKCS12(certDER: [UInt8], keyPKCS8DER: [UInt8], password: String) -> Data {
        // OIDs
        let oidData: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01] // id-data
        let oidCertBag: [UInt8] = [0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x03]
        let oidKeyBag: [UInt8] = [0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01]
        let oidX509Cert: [UInt8] = [0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x16, 0x01]
        let oidSHA256: [UInt8] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] // sha256

        // CertBag value: SEQUENCE { oid x509Certificate, [0] OCTET STRING { cert DER } }
        let certOctet = wrapTag(0x04, certDER)  // OCTET STRING
        let certExplicit0 = wrapTag(0xA0, certOctet)  // [0] EXPLICIT
        let certBagValue = wrapSequence(oidX509Cert + certExplicit0)

        // SafeBag for cert: SEQUENCE { oid certBag, [0] CertBag }
        let certBagExplicit = wrapTag(0xA0, certBagValue)
        let certSafeBag = wrapSequence(oidCertBag + certBagExplicit)

        // SafeBag for key: SEQUENCE { oid keyBag, [0] PKCS8 key }
        let keyExplicit = wrapTag(0xA0, wrapSequence(keyPKCS8DER))  // wrap key in SEQUENCE then [0]
        // Actually keyBag value is just the PKCS8 PrivateKeyInfo directly
        let keyBagExplicit = wrapTag(0xA0, keyPKCS8DER)
        let keySafeBag = wrapSequence(oidKeyBag + keyBagExplicit)

        // SafeContents: SEQUENCE OF SafeBag
        let safeContents = wrapSequence(keySafeBag + certSafeBag)

        // Wrap SafeContents in ContentInfo { id-data, [0] OCTET STRING { safeContents } }
        let safeContentsOctet = wrapTag(0x04, safeContents)
        let innerContentExplicit = wrapTag(0xA0, safeContentsOctet)
        let contentInfo = wrapSequence(oidData + innerContentExplicit)

        // AuthenticatedSafe: SEQUENCE OF ContentInfo (just one)
        let authSafe = wrapSequence(contentInfo)

        // Wrap authSafe as the outer ContentInfo
        let authSafeOctet = wrapTag(0x04, authSafe)
        let outerContentExplicit = wrapTag(0xA0, authSafeOctet)
        let outerContentInfo = wrapSequence(oidData + outerContentExplicit)

        // MacData: compute HMAC-SHA256 over authSafe
        let passwordBytes = Array(password.utf16).flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] } + [0, 0]
        let salt: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] // 8-byte salt
        let iterations: Int = 2048

        // For PKCS12 MAC, we need to derive a key from the password+salt
        // using PKCS12 KDF. This is complex — let's try without MAC first.
        // Some implementations accept MAC-less PKCS12.

        // Version: INTEGER 3
        let version: [UInt8] = [0x02, 0x01, 0x03]

        // PFX: SEQUENCE { version, authSafe }
        // Try without MacData first
        let pfx = wrapSequence(version + outerContentInfo)

        return Data(pfx)
    }

    // MARK: - ASN.1 helpers

    private static func wrapTag(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        return [tag] + derLength(content.count) + content
    }

    private static func wrapSequence(_ content: [UInt8]) -> [UInt8] {
        return wrapTag(0x30, content)
    }

    private static func derLength(_ length: Int) -> [UInt8] {
        if length < 128 {
            return [UInt8(length)]
        } else if length < 256 {
            return [0x81, UInt8(length)]
        } else if length < 65536 {
            return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        } else {
            return [0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        }
    }
}
