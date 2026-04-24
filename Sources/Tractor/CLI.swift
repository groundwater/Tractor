import ArgumentParser
import Foundation

/// If launched via a symlink, re-exec from the real path so that
/// NSBundle.main resolves to the .app bundle. This is required for
/// NETunnelProviderManager.saveToPreferences to find the sysext.
private func reexecIfSymlinked() {
    let fm = FileManager.default
    let argv0 = ProcessInfo.processInfo.arguments[0]
    guard let realPath = try? fm.destinationOfSymbolicLink(atPath: argv0) else { return }
    // Already running from the real path
    if argv0 == realPath { return }
    // Re-exec from the resolved path
    var args = ProcessInfo.processInfo.arguments
    args[0] = realPath
    let cArgs = args.map { strdup($0) } + [nil]
    execv(realPath, cArgs)
    // execv only returns on error
}

@main
struct Tractor: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "tractor",
        abstract: "Monitor AI coding agent activity via Endpoint Security",
        subcommands: [Trace.self]
    )

    static func main() {
        reexecIfSymlinked()
        Self.main(nil)
    }
}
