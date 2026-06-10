import Foundation

/// Shared tokenizer behind the minimal JavaScript syntax highlighting used by
/// both the read-only script display (ScriptsView) and the editable playground
/// editor (CodeEditorView). Produces non-overlapping token runs; the renderers
/// map token kinds to their own color types (SwiftUI Color vs NSColor).
enum JSSyntax {
    enum Token {
        case comment, string, builtin, keyword, number
    }

    private struct Rule { let regex: NSRegularExpression; let token: Token; let priority: Int }

    /// Functions and values the JS engine registers as globals — keep in sync
    /// with the `setObject(_:forKeyedSubscript:)` calls in JSEngine.swift.
    private static let builtins = [
        "probe", "emit", "render", "deny", "log", "args", "engineStats",
        "listPids", "listProcs", "getProc", "getProcStats", "getAncestry",
        "getAncestryNames", "getFdPipe", "terminalCols", "terminalRows",
        "loadAverage", "ncpu",
    ].joined(separator: "|")

    private static let rules: [Rule] = build([
        // Order matters — earlier rules win on overlap, which makes
        // strings/comments correctly outrank keywords inside them.
        (#"/\*[\s\S]*?\*/"#, .comment),
        (#"//[^\n]*"#, .comment),
        (#"`(?:\\.|[^`\\])*`"#, .string),
        (#""(?:\\.|[^"\\])*""#, .string),
        (#"'(?:\\.|[^'\\])*'"#, .string),
        ("\\b(\(builtins))\\b", .builtin),
        (#"\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|typeof|instanceof|in|of|this|null|undefined|true|false|throw|try|catch|finally|class|extends|import|export|from|as|async|await|yield)\b"#, .keyword),
        (#"\b\d+(?:\.\d+)?\b"#, .number),
    ])

    private static func build(_ specs: [(String, Token)]) -> [Rule] {
        specs.enumerated().compactMap { (i, spec) in
            guard let r = try? NSRegularExpression(pattern: spec.0) else { return nil }
            return Rule(regex: r, token: spec.1, priority: i)
        }
    }

    /// Non-overlapping token runs in UTF-16 (NSRange) coordinates, sorted by
    /// location.
    static func runs(in text: String) -> [(range: NSRange, token: Token)] {
        let full = NSRange(location: 0, length: (text as NSString).length)
        var all: [(range: NSRange, token: Token, priority: Int)] = []
        for rule in rules {
            rule.regex.enumerateMatches(in: text, range: full) { m, _, _ in
                if let m = m { all.append((m.range, rule.token, rule.priority)) }
            }
        }
        all.sort { a, b in
            if a.range.location != b.range.location { return a.range.location < b.range.location }
            return a.priority < b.priority
        }
        var picked: [(range: NSRange, token: Token)] = []
        var lastEnd = 0
        for m in all where m.range.location >= lastEnd {
            picked.append((m.range, m.token))
            lastEnd = m.range.location + m.range.length
        }
        return picked
    }
}
