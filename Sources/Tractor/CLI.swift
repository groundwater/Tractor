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
            fputs("\nStopped. Extension stays running.\n", stderr)
            Foundation.exit(0)
        }
        sigintSource.resume()
        dispatchMain()
    }
}
