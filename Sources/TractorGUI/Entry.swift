import Foundation

/// Single @main entry point for the unified Tractor binary. Mode is selected
/// via the TRACTOR_CLI environment variable, set by the
/// Contents/Resources/tractor shell wrapper when invoked from a shell.
/// LaunchServices-launched starts (Finder double-click, `open`) don't set
/// the var → GUI mode.
@main
enum TractorEntry {
    static func main() {
        if ProcessInfo.processInfo.environment["TRACTOR_CLI"] != nil {
            Tractor.main(nil)
        } else {
            TractorGUIEntry.run()
        }
    }
}
