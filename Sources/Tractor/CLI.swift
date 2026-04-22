import ArgumentParser

@main
struct Tractor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "tractor",
        abstract: "Monitor AI coding agent activity via Endpoint Security",
        subcommands: [Trace.self]
    )
}
