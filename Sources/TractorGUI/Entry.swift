import Foundation

/// Single @main entry point for the unified Tractor binary. CLI mode is
/// selected by the TRACTOR_CLI environment variable (set by the
/// Contents/Resources/tractor shell wrapper) or by the presence of CLI
/// arguments, so invoking the binary directly (`Tractor.app/Contents/MacOS/
/// Tractor --help`) doesn't silently launch the GUI and hang the shell.
/// LaunchServices-launched starts (Finder double-click, `open`) pass no
/// arguments, or only `-psn_…`/`-NS…`/`-Apple…` flags → GUI mode.
@main
enum TractorEntry {
    static func main() {
        if ProcessInfo.processInfo.environment["TRACTOR_CLI"] != nil || hasCLIArguments {
            Tractor.main(nil)
        } else {
            TractorGUIEntry.run()
        }
    }

    private static var hasCLIArguments: Bool {
        guard let first = CommandLine.arguments.dropFirst().first else { return false }
        return !["-psn_", "-NS", "-Apple"].contains { first.hasPrefix($0) }
    }
}
