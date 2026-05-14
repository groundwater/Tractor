import ArgumentParser
import Foundation
import NetworkExtension

struct Tractor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "tractor",
        abstract: "Monitor AI coding agent activity via Endpoint Security",
        subcommands: [Trace.self, Exec.self, Activate.self, Log.self]
    )

    static func main(_ arguments: [String]? = nil) {
        do {
            var command = try parseAsRoot(arguments)
            try command.run()
        } catch let error as CleanExit {
            exit(withError: error)
        } catch {
            let exitCode = Self.exitCode(for: error)
            if exitCode == .success {
                exit(withError: error)
            }

            let message = Self.message(for: error)
            if !message.isEmpty {
                fputs("\(Self._errorPrefix)\(message)\n", stderr)
            }
            Foundation.exit(exitCode.rawValue)
        }
    }
}

struct Activate: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "activate",
        abstract: "Activate a Tractor system component",
        subcommands: [ActivateEndpointSecurity.self, ActivateNetworkExtension.self, ActivateCertificateRoot.self]
    )
}

struct TrustCA: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "trust-ca",
        abstract: "Generate (if needed) and trust the MITM CA certificate"
    )

    @Flag(name: .long, help: "Only export the CA PEM to stdout without installing")
    var exportOnly: Bool = false

    struct CAPaths {
        let dir: String
        let keyPath: String
        let certPath: String
    }

    private static let appGroupID = "group.com.jacobgroundwater.Tractor"

    static func caPaths() throws -> CAPaths {
        let fm = FileManager.default
        guard let url = fm.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            throw ValidationError("Cannot resolve Tractor app group container. Install Tractor first, then retry.")
        }
        let dir = url.path
        return CAPaths(dir: dir, keyPath: dir + "/mitm-ca.key", certPath: dir + "/mitm-ca.pem")
    }

    static func requiredExistingCAPaths() throws -> CAPaths {
        let paths = try caPaths()
        guard FileManager.default.fileExists(atPath: paths.certPath),
              FileManager.default.fileExists(atPath: paths.keyPath) else {
            throw ValidationError("MITM requires CA files at \(paths.dir). Run 'sudo tractor activate certificate-root' first.")
        }
        return paths
    }

    func run() throws {
        let paths = try Self.caPaths()

        // Generate CA if it doesn't exist
        if !FileManager.default.fileExists(atPath: paths.certPath) {
            fputs("Generating new MITM CA...\n", stderr)
            try Self.runOpenSSL(["ecparam", "-genkey", "-name", "prime256v1", "-out", paths.keyPath])
            try Self.runOpenSSL(["req", "-new", "-x509", "-key", paths.keyPath,
                                 "-out", paths.certPath, "-days", "3650",
                                 "-subj", "/CN=Tractor MITM CA/O=Tractor"])
            fputs("CA generated at \(paths.dir)\n", stderr)
        } else {
            fputs("Using existing CA at \(paths.dir)\n", stderr)
        }

        let pem = try String(contentsOfFile: paths.certPath, encoding: .utf8)

        if exportOnly {
            print(pem)
            return
        }

        // 1. Remove old Tractor certs from keychain
        fputs("Removing old Tractor MITM CA certs from keychain...\n", stderr)
        for _ in 0..<20 {
            let del = Process()
            del.executableURL = URL(fileURLWithPath: "/usr/bin/security")
            del.arguments = ["delete-certificate", "-c", "Tractor MITM CA",
                             "/Library/Keychains/System.keychain"]
            del.standardOutput = FileHandle.nullDevice
            del.standardError = FileHandle.nullDevice
            try? del.run()
            del.waitUntilExit()
            if del.terminationStatus != 0 { break }
        }

        // 2. Add to system keychain
        fputs("Installing CA into system keychain...\n", stderr)
        try Self.runProcess("/usr/bin/security",
                            ["add-trusted-cert", "-d", "-r", "trustRoot",
                             "-k", "/Library/Keychains/System.keychain", paths.certPath])

        // 3. Add to /etc/ssl/cert.pem
        fputs("Installing CA into /etc/ssl/cert.pem...\n", stderr)
        let certPemPath = "/etc/ssl/cert.pem"
        var certPem = try String(contentsOfFile: certPemPath, encoding: .utf8)
        // Remove previous entry
        let marker = "\n# Tractor MITM CA — added by tractor trust-ca\n"
        if let range = certPem.range(of: marker) {
            certPem = String(certPem[certPem.startIndex..<range.lowerBound])
        }
        certPem += marker + pem + "\n"
        try certPem.write(toFile: certPemPath, atomically: true, encoding: .utf8)

        fputs("CA trusted (keychain + /etc/ssl/cert.pem).\n", stderr)
    }

    static func runOpenSSL(_ args: [String]) throws {
        try runProcess("/usr/bin/openssl", args)
    }

    static func runProcess(_ path: String, _ args: [String]) throws {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try proc.run()
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else {
            fatalError("\(path) \(args.first ?? "") failed with exit \(proc.terminationStatus)")
        }
    }
}

struct ActivateEndpointSecurity: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "endpoint-security",
        abstract: "Activate the Endpoint Security extension (one-time setup)"
    )

    func run() throws {
        let pm = ProxyManager()
        pm.activateES { error in
            if let error = error {
                fputs("Error: \(error)\n", stderr)
                Foundation.exit(1)
            }
            fputs("Endpoint Security extension activated.\n", stderr)
            Foundation.exit(0)
        }
        dispatchMain()
    }
}

struct ActivateNetworkExtension: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "network-extension",
        abstract: "Activate the network extension (optional)"
    )

    func run() throws {
        let pm = ProxyManager()
        pm.activateNetwork { error in
            if let error = error {
                fputs("Error: \(error)\n", stderr)
                Foundation.exit(1)
            }
            fputs("Network extension activated.\n", stderr)
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                Foundation.exit(0)
            }
        }
        dispatchMain()
    }
}

struct ActivateCertificateRoot: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "certificate-root",
        abstract: "Install the Tractor MITM CA into system trust stores"
    )

    func run() throws {
        try TrustCA().run()
    }
}
