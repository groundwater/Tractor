import Foundation

/// Discovers JS scripts available to the Playground. Two sources:
///   - **Built-in**: `examples/` directory bundled inside the .app at
///     build time (read-only; edits prompt "Save As Copy").
///   - **User**: `~/Library/Application Support/Tractor/scripts/` — the
///     conventional Application Support location. Writable; auto-loaded
///     and visible in the sidebar.
///
/// Both lists are sorted alphabetically by filename.
@MainActor
final class ScriptLibrary: ObservableObject {
    /// Shared instance — lives for the app's lifetime so the Playground's
    /// list state survives tab teardowns.
    static let shared: ScriptLibrary = {
        let l = ScriptLibrary()
        l.reload()
        return l
    }()

    struct Script: Identifiable, Hashable {
        let id: String          // "builtin:<name>" or "user:<name>"
        let name: String        // basename without .js
        let url: URL
        let isBuiltIn: Bool
    }

    @Published private(set) var builtins: [Script] = []
    @Published private(set) var custom: [Script] = []

    /// `~/Library/Application Support/Tractor/scripts/` — created lazily.
    static let customDir: URL = {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory,
                                                  in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory() + "/Library/Application Support")
        let dir = appSupport
            .appendingPathComponent("Tractor", isDirectory: true)
            .appendingPathComponent("scripts", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    /// Bundled examples directory inside the .app. When running unbundled
    /// (debug `swift run`), falls back to the repo's `examples/` folder
    /// relative to the source so the playground is usable from a dev build.
    static let builtinsDir: URL? = {
        if let res = Bundle.main.resourceURL?.appendingPathComponent("examples", isDirectory: true),
           FileManager.default.fileExists(atPath: res.path) {
            return res
        }
        // Dev fallback: walk up from this source file to find `examples/`.
        let here = URL(fileURLWithPath: #filePath)
        var dir = here.deletingLastPathComponent()
        for _ in 0..<6 {
            let candidate = dir.appendingPathComponent("examples", isDirectory: true)
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            dir = dir.deletingLastPathComponent()
        }
        return nil
    }()

    func reload() {
        builtins = loadFrom(Self.builtinsDir, isBuiltIn: true)
        custom   = loadFrom(Self.customDir,  isBuiltIn: false)
    }

    private func loadFrom(_ dir: URL?, isBuiltIn: Bool) -> [Script] {
        guard let dir = dir,
              let items = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: nil)
        else { return [] }
        let prefix = isBuiltIn ? "builtin" : "user"
        return items
            .filter { $0.pathExtension == "js" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { url in
                let name = url.deletingPathExtension().lastPathComponent
                return Script(id: "\(prefix):\(name)", name: name,
                              url: url, isBuiltIn: isBuiltIn)
            }
    }

    /// Read the on-disk source for a script.
    func source(of script: Script) -> String {
        (try? String(contentsOf: script.url, encoding: .utf8)) ?? ""
    }

    /// Write a user script. If `existingURL` is non-nil we overwrite
    /// (rename-aware). Otherwise we create a new file in `customDir`.
    /// Returns the resulting Script. Throws on I/O failure.
    @discardableResult
    func saveUserScript(name: String, source: String, overwriting existingURL: URL? = nil) throws -> Script {
        let safeName = sanitize(name)
        let url = existingURL ?? Self.customDir.appendingPathComponent(safeName + ".js")
        try source.data(using: .utf8)!.write(to: url, options: .atomic)
        reload()
        return Script(id: "user:\(safeName)", name: safeName, url: url, isBuiltIn: false)
    }

    func deleteUserScript(_ script: Script) throws {
        guard !script.isBuiltIn else { return }
        try FileManager.default.removeItem(at: script.url)
        reload()
    }

    /// Strip path separators and trim. Empty input becomes "untitled".
    private func sanitize(_ raw: String) -> String {
        let cleaned = raw
            .replacingOccurrences(of: "/", with: "-")
            .replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty ? "untitled" : cleaned
    }
}

/// Shell-style argument splitter. Whitespace separated, supports single
/// and double quotes and backslash escaping inside double-quoted strings.
/// Matches what `tractor program <file>` sees as `args[]` on the CLI.
enum ShellArgs {
    static func parse(_ input: String) -> [String] {
        var out: [String] = []
        var current = ""
        var inQuote: Character? = nil
        var escape = false
        for c in input {
            if escape {
                current.append(c); escape = false; continue
            }
            if c == "\\" && inQuote != "'" { escape = true; continue }
            if let q = inQuote {
                if c == q { inQuote = nil } else { current.append(c) }
                continue
            }
            if c == "\"" || c == "'" { inQuote = c; continue }
            if c.isWhitespace {
                if !current.isEmpty { out.append(current); current = "" }
                continue
            }
            current.append(c)
        }
        if !current.isEmpty { out.append(current) }
        return out
    }
}
