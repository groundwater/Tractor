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
            fputs("Network extension running. Press Ctrl-C to stop.\n", stderr)
        }
        // Stay alive — the tunnel needs this process to remain running
        signal(SIGINT, SIG_IGN)
        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler {
            fputs("\nRemoving proxy config...\n", stderr)
            NETransparentProxyManager.loadAllFromPreferences { managers, _ in
                for m in managers ?? [] {
                    m.removeFromPreferences { _ in }
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
                    fputs("Done.\n", stderr)
                    Foundation.exit(0)
                }
            }
        }
        sigintSource.resume()
        dispatchMain()
    }
}
