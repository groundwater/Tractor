import AppKit
import SwiftUI

/// Editable JavaScript source view with syntax highlighting. SwiftUI's
/// TextEditor doesn't expose attributed text in macOS 15, so we wrap
/// `NSTextView` directly and re-apply highlight rules on every edit.
struct CodeEditorView: NSViewRepresentable {
    @Binding var text: String
    var isEditable: Bool = true

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
    }
}

// MARK: - Highlighter for NSTextStorage

/// Renders the shared `JSSyntax` token runs with NSColor values so we can
/// apply directly to a live `NSTextStorage` without going through SwiftUI's
/// AttributedString.
private enum JSEditorHighlighter {
    private static func color(for token: JSSyntax.Token) -> NSColor {
        switch token {
        case .comment: return .secondaryLabelColor
        case .string: return .string
        case .builtin: return .controlAccentColor
        case .keyword: return .keyword
        case .number: return .number
        }
    }

    static func apply(to storage: NSTextStorage, text: String, font: NSFont) {
        storage.beginEditing()
        let full = NSRange(location: 0, length: (text as NSString).length)
        storage.setAttributes([
            .foregroundColor: NSColor.labelColor,
            .font: font,
        ], range: full)
        for run in JSSyntax.runs(in: text) {
            storage.addAttribute(.foregroundColor, value: color(for: run.token), range: run.range)
        }
        storage.endEditing()
    }
}

private extension NSColor {
    static var string: NSColor  { NSColor(red: 0.78, green: 0.41, blue: 0.20, alpha: 1) }
    static var keyword: NSColor { NSColor(red: 0.78, green: 0.31, blue: 0.55, alpha: 1) }
    static var number: NSColor  { NSColor(red: 0.40, green: 0.30, blue: 0.78, alpha: 1) }
}
