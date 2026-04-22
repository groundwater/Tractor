import ArgumentParser

@main
struct GhostBuster: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ghostbuster",
        abstract: "Monitor AI coding agent activity via Endpoint Security",
        subcommands: [Trace.self]
    )
}
