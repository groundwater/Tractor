import ArgumentParser
import Foundation
import NetworkExtension

@main
struct Tractor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "tractor",
        abstract: "Monitor AI coding agent activity via Endpoint Security",
        subcommands: [Trace.self, Activate.self]
    )
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
