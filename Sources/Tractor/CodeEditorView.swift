import AppKit
import SwiftUI

/// Editable JavaScript source view with syntax highlighting. SwiftUI's
/// TextEditor doesn't expose attributed text in macOS 15, so we wrap
/// `NSTextView` directly and re-apply highlight rules on every edit.
struct CodeEditorView: NSViewRepresentable {
    @Binding var text: String
    var isEditable: Bool = true
    var onSaveRequested: (() -> Void)? = nil   // fired on Cmd-S
    var onRunRequested: (() -> Void)? = nil    // fired on Cmd-R

    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSTextView.scrollableTextView()
        let tv = scroll.documentView as! NSTextView
        tv.delegate = context.coordinator
        tv.font = Self.font
        tv.isAutomaticQuoteSubstitutionEnabled = false
        tv.isAutomaticDashSubstitutionEnabled = false
        tv.isAutomaticTextReplacementEnabled = false
        tv.isAutomaticSpellingCorrectionEnabled = false
        tv.isAutomaticLinkDetectionEnabled = false
        tv.isAutomaticDataDetectionEnabled = false
        tv.isRichText = false
        tv.allowsUndo = true
        tv.usesFindBar = true
        tv.isIncrementalSearchingEnabled = true
        tv.textContainerInset = NSSize(width: 8, height: 8)
        tv.string = text
        tv.isEditable = isEditable
        tv.typingAttributes = [
            .foregroundColor: NSColor.labelColor,
            .font: Self.font,
        ]
        if let storage = tv.textStorage {
            JSEditorHighlighter.apply(to: storage, text: text, font: Self.font)
        }
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = false
        scroll.autohidesScrollers = true
        return scroll
    }

    func updateNSView(_ scroll: NSScrollView, context: Context) {
        let tv = scroll.documentView as! NSTextView
        if tv.string != text {
            // Programmatic update (e.g. switched to a different script).
            // Reset undo so the previous file's history doesn't bleed in.
            tv.undoManager?.removeAllActions()
            let sel = tv.selectedRange()
            tv.string = text
            tv.setSelectedRange(NSRange(location: min(sel.location, text.utf16.count),
                                        length: 0))
            if let storage = tv.textStorage {
                JSEditorHighlighter.apply(to: storage, text: text, font: Self.font)
            }
        }
        if tv.isEditable != isEditable { tv.isEditable = isEditable }
        context.coordinator.parent = self
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    static let font: NSFont = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)

    final class Coordinator: NSObject, NSTextViewDelegate {
        var parent: CodeEditorView
        init(_ parent: CodeEditorView) { self.parent = parent }

        func textDidChange(_ note: Notification) {
            guard let tv = note.object as? NSTextView else { return }
            // Push the new text up to SwiftUI state without provoking
            // updateNSView to clobber the undo stack — string compare in
            // updateNSView guards that.
            parent.text = tv.string
            if let storage = tv.textStorage {
                JSEditorHighlighter.apply(to: storage, text: tv.string,
                                          font: CodeEditorView.font)
            }
        }

        func textView(_ textView: NSTextView, doCommandBy sel: Selector) -> Bool {
            // We hook Cmd-S and Cmd-R via the responder chain elsewhere
            // (PlaygroundView menu commands). Nothing to override here yet.
            return false
        }
    }
}

// MARK: - Highlighter for NSTextStorage

/// Same rule set as `JSHighlighter` (used by ScriptsView's read-only
/// display) but with NSColor values so we can apply directly to a live
/// `NSTextStorage` without going through SwiftUI's AttributedString.
private enum JSEditorHighlighter {
    private struct Rule { let regex: NSRegularExpression; let color: NSColor; let priority: Int }

    private static let rules: [Rule] = build([
        // Order matters — earlier rules win on overlap.
        (#"/\*[\s\S]*?\*/"#,                 NSColor.secondaryLabelColor),
        (#"//[^\n]*"#,                       NSColor.secondaryLabelColor),
        (#"`(?:\\.|[^`\\])*`"#,              NSColor.string),
        (#""(?:\\.|[^"\\])*""#,              NSColor.string),
        (#"'(?:\\.|[^'\\])*'"#,              NSColor.string),
        (#"\b(probe|emit|render|log|args|engineStats|listPids|listProcs|getProc|getProcStats|getAncestry|getAncestryNames|getFdPipe|terminalCols|terminalRows|loadAverage|ncpu)\b"#,
                                              NSColor.controlAccentColor),
        (#"\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|typeof|instanceof|in|of|this|null|undefined|true|false|throw|try|catch|finally|class|extends|import|export|from|as|async|await|yield)\b"#,
                                              NSColor.keyword),
        (#"\b\d+(?:\.\d+)?\b"#,              NSColor.number),
    ])

    private static func build(_ specs: [(String, NSColor)]) -> [Rule] {
        specs.enumerated().compactMap { (i, spec) in
            guard let r = try? NSRegularExpression(pattern: spec.0) else { return nil }
            return Rule(regex: r, color: spec.1, priority: i)
        }
    }

    static func apply(to storage: NSTextStorage, text: String, font: NSFont) {
        storage.beginEditing()
        let nsText = text as NSString
        let full = NSRange(location: 0, length: nsText.length)
        storage.setAttributes([
            .foregroundColor: NSColor.labelColor,
            .font: font,
        ], range: full)

        var all: [(range: NSRange, color: NSColor, priority: Int)] = []
        for rule in rules {
            rule.regex.enumerateMatches(in: text, range: full) { m, _, _ in
                if let m = m { all.append((m.range, rule.color, rule.priority)) }
            }
        }
        all.sort { a, b in
            if a.range.location != b.range.location { return a.range.location < b.range.location }
            return a.priority < b.priority
        }
        var lastEnd = 0
        for m in all where m.range.location >= lastEnd {
            storage.addAttribute(.foregroundColor, value: m.color, range: m.range)
            lastEnd = m.range.location + m.range.length
        }
        storage.endEditing()
    }
}

private extension NSColor {
    static var string: NSColor  { NSColor(red: 0.78, green: 0.41, blue: 0.20, alpha: 1) }
    static var keyword: NSColor { NSColor(red: 0.78, green: 0.31, blue: 0.55, alpha: 1) }
    static var number: NSColor  { NSColor(red: 0.40, green: 0.30, blue: 0.78, alpha: 1) }
}
