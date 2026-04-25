import ArgumentParser
import Foundation
import NetworkExtension

@main
struct Tractor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "tractor",
        abstract: "Monitor AI coding agent activity via Endpoint Security",
        subcommands: [Trace.self, Activate.self, TrustCA.self]
    )
}

struct TrustCA: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "trust-ca",
        abstract: "Generate (if needed) and trust the MITM CA certificate"
    )

    @Flag(name: .long, help: "Only export the CA PEM to stdout without installing")
    var exportOnly: Bool = false

    static let caDir: String = {
        let fm = FileManager.default
        guard let url = fm.containerURL(forSecurityApplicationGroupIdentifier: "group.com.jacobgroundwater.Tractor") else {
            fatalError("Cannot resolve app group container")
        }
        return url.path
    }()
    static var caKeyPath: String { caDir + "/mitm-ca.key" }
    static var caCertPath: String { caDir + "/mitm-ca.pem" }

    func run() throws {
        // Generate CA if it doesn't exist
        if !FileManager.default.fileExists(atPath: Self.caCertPath) {
            fputs("Generating new MITM CA...\n", stderr)
            try Self.runOpenSSL(["ecparam", "-genkey", "-name", "prime256v1", "-out", Self.caKeyPath])
            try Self.runOpenSSL(["req", "-new", "-x509", "-key", Self.caKeyPath,
                                 "-out", Self.caCertPath, "-days", "3650",
                                 "-subj", "/CN=Tractor MITM CA/O=Tractor"])
            fputs("CA generated at \(Self.caDir)\n", stderr)
        } else {
            fputs("Using existing CA at \(Self.caDir)\n", stderr)
        }

        let pem = try String(contentsOfFile: Self.caCertPath, encoding: .utf8)

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
                             "-k", "/Library/Keychains/System.keychain", Self.caCertPath])

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

struct Activate: ParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Activate the network extension (one-time setup)"
    )

    func run() throws {
        let pm = ProxyManager()
        pm.activate { error in
            if let error = error {
                fputs("Error: \(error)\n", stderr)
                Foundation.exit(1)
            }
            fputs("Network extension activated.\n", stderr)
            // Give the tunnel a moment to fully connect before exiting
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                Foundation.exit(0)
            }
        }
        dispatchMain()
    }
}
