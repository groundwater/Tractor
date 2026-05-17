import SwiftUI

/// Scripts tab: shows the JS probe program(s) currently loaded into the ES
/// extension. Today the engine holds at most one program at a time, so the
/// list is one row or empty. Structured as a List so multi-program support
/// drops in later without redesigning the tab.
struct ScriptsView: View {
    @StateObject private var model = ScriptsModel()
    @State private var selection: String? = nil

    var body: some View {
        HSplitView {
            // Left: list of loaded programs.
            VStack(spacing: 0) {
                if model.programs.isEmpty {
                    emptyState
                } else {
                    List(selection: $selection) {
                        ForEach(model.programs, id: \.id) { p in
                            ScriptRow(program: p)
                                .tag(p.id)
                        }
                    }
                    .listStyle(.inset)
                }
            }
            .frame(minWidth: 260, idealWidth: 320)

            // Right: source of selected program. Both branches pin the
            // same minimum width so HSplitView doesn't snap the divider
            // when switching between "selected" and "no selection".
            Group {
                if let id = selection, let p = model.programs.first(where: { $0.id == id }) {
                    ScriptDetail(program: p)
                } else {
                    Text("Select a script to view its source.")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .frame(minWidth: 420, idealWidth: 600, maxWidth: .infinity,
                   maxHeight: .infinity)
            .layoutPriority(1)
        }
        .onAppear { model.start() }
        .onDisappear { model.stop() }
        .onChange(of: model.programs.map(\.id)) { _, ids in
            if selection == nil || !ids.contains(selection ?? "") {
                selection = ids.first
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text("No scripts loaded")
                .font(.headline)
            Text(verbatim: "Submit one with:\n  sudo tractor program <file.js>")
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

private struct ScriptRow: View {
    let program: ScriptsModel.Program

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(program.title)
                .font(.headline)
                .lineLimit(1)
            HStack(spacing: 6) {
                Image(systemName: "circle.fill")
                    .font(.system(size: 6))
                    .foregroundStyle(.green)
                Text(verbatim: "\(program.probes.count) probe\(program.probes.count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("·")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(verbatim: program.loadedAtRelative)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct ScriptDetail: View {
    let program: ScriptsModel.Program
    @StateObject private var emits = EmitsModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(program.title).font(.headline)
                Spacer()
                Text(program.loadedAtAbsolute)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            // Probes
            VStack(alignment: .leading, spacing: 4) {
                Text("Probes")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                FlowLayout(spacing: 6) {
                    ForEach(program.probes, id: \.self) { name in
                        Text(name)
                            .font(.system(.caption, design: .monospaced))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.accentColor.opacity(0.15))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                    }
                }
            }
            .padding(12)

            Divider()

            // Source on top, live output on bottom — user-resizable.
            VSplitView {
                ScrollView {
                    Text(JSHighlighter.highlight(program.source))
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(12)
                }
                .frame(minHeight: 120, idealHeight: 220)

                EmitsTable(emits: emits)
                    .frame(minHeight: 160, idealHeight: 280)
            }
        }
        .onAppear { emits.start() }
        .onDisappear { emits.stop() }
    }
}

// MARK: - JS syntax highlighter

/// Minimal JavaScript syntax highlighter. Emits an AttributedString that
/// SwiftUI Text can render directly. Patterns are evaluated in declaration
/// order; the first match wins for any given character range, which makes
/// strings/comments correctly outrank keywords inside them.
private enum JSHighlighter {
    private struct Rule { let regex: NSRegularExpression; let color: Color; let priority: Int }

    private static let rules: [Rule] = build([
        // (pattern, color)  — order is priority (lower = higher)
        (#"/\*[\s\S]*?\*/"#,                                                                Color.secondary),                              // /* block */
        (#"//[^\n]*"#,                                                                       Color.secondary),                              // // line
        (#"`(?:\\.|[^`\\])*`"#,                                                              Color(red: 0.78, green: 0.41, blue: 0.20)),    // `template`
        (#""(?:\\.|[^"\\])*""#,                                                              Color(red: 0.78, green: 0.41, blue: 0.20)),    // "double"
        (#"'(?:\\.|[^'\\])*'"#,                                                              Color(red: 0.78, green: 0.41, blue: 0.20)),    // 'single'
        (#"\b(probe|emit|track|untrack|log)\b"#,                                             Color.accentColor),                            // DSL builtins
        (#"\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|typeof|instanceof|in|of|this|null|undefined|true|false|throw|try|catch|finally|class|extends|import|export|from|as|async|await|yield)\b"#,
                                                                                              Color(red: 0.78, green: 0.31, blue: 0.55)),    // keywords
        (#"\b\d+(?:\.\d+)?\b"#,                                                              Color(red: 0.40, green: 0.30, blue: 0.78)),    // numbers
    ])

    private static func build(_ specs: [(String, Color)]) -> [Rule] {
        return specs.enumerated().compactMap { (i, spec) in
            guard let r = try? NSRegularExpression(pattern: spec.0, options: []) else { return nil }
            return Rule(regex: r, color: spec.1, priority: i)
        }
    }

    static func highlight(_ source: String) -> AttributedString {
        let full = NSRange(source.startIndex..<source.endIndex, in: source)
        var all: [(range: NSRange, color: Color, priority: Int)] = []
        for rule in rules {
            rule.regex.enumerateMatches(in: source, range: full) { m, _, _ in
                if let m = m { all.append((m.range, rule.color, rule.priority)) }
            }
        }
        all.sort { a, b in
            if a.range.location != b.range.location { return a.range.location < b.range.location }
            return a.priority < b.priority
        }
        var picked: [(NSRange, Color)] = []
        var lastEnd = 0
        for m in all where m.range.location >= lastEnd {
            picked.append((m.range, m.color))
            lastEnd = m.range.location + m.range.length
        }

        var result = AttributedString()
        var cursor = 0
        let utf16Count = source.utf16.count
        for (range, color) in picked {
            if range.location > cursor,
               let gap = Range(NSRange(location: cursor, length: range.location - cursor), in: source) {
                // Plain gap — explicit default foreground so SwiftUI doesn't
                // inherit the previous run's color across the boundary.
                var plain = AttributeContainer()
                plain.foregroundColor = Color.primary
                result.append(AttributedString(String(source[gap]), attributes: plain))
            }
            if let r = Range(range, in: source) {
                var attrs = AttributeContainer()
                attrs.foregroundColor = color
                result.append(AttributedString(String(source[r]), attributes: attrs))
            }
            cursor = range.location + range.length
        }
        if cursor < utf16Count,
           let tail = Range(NSRange(location: cursor, length: utf16Count - cursor), in: source) {
            var plain = AttributeContainer()
            plain.foregroundColor = Color.primary
            result.append(AttributedString(String(source[tail]), attributes: plain))
        }
        return result
    }
}

// MARK: - Live emits table

private struct EmitsTable: View {
    @ObservedObject var emits: EmitsModel
    @State private var autoScroll: Bool = true

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss.SSS"; return f
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Text("Live Output")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                Text(verbatim: "\(emits.records.count) record\(emits.records.count == 1 ? "" : "s")")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Toggle("Auto-scroll", isOn: $autoScroll)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                Button("Clear") { emits.clear() }
                    .controlSize(.small)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)

            Divider()

            ScrollViewReader { proxy in
                Table(emits.records) {
                    TableColumn("Time") { r in
                        Text(Self.timeFormatter.string(from: r.time))
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 90, ideal: 100, max: 110)

                    TableColumn("Program") { r in
                        Text(r.program)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 80, ideal: 110, max: 160)

                    TableColumn("Channel") { r in
                        Text(r.channel)
                            .font(.system(.caption, design: .monospaced))
                    }
                    .width(min: 100, ideal: 140, max: 200)

                    TableColumn("Payload") { r in
                        Text(r.payloadJSON)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .help(r.payloadJSON)
                            .textSelection(.enabled)
                    }
                }
                .onChange(of: emits.records.count) { _, _ in
                    guard autoScroll, let last = emits.records.last else { return }
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
    }
}

@MainActor
final class EmitsModel: ObservableObject {
    @Published private(set) var records: [EmitRecord] = []

    private var timer: Timer?
    private let maxRows = 500

    func start() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func stop() {
        timer?.invalidate(); timer = nil
    }

    func clear() {
        records = []
    }

    private func refresh() {
        DispatchQueue.global(qos: .userInitiated).async {
            let new = ESXPCClient.fetchEmits()
            guard !new.isEmpty else { return }
            Task { @MainActor in
                self.records.append(contentsOf: new)
                if self.records.count > self.maxRows {
                    self.records.removeFirst(self.records.count - self.maxRows)
                }
            }
        }
    }
}

/// Tiny non-clipping flow layout for the probe chips. macOS 13+ Layout API.
private struct FlowLayout: Layout {
    var spacing: CGFloat = 6
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x + s.width > maxWidth, x > 0 { x = 0; y += rowHeight + spacing; rowHeight = 0 }
            x += s.width + spacing
            rowHeight = max(rowHeight, s.height)
        }
        return CGSize(width: maxWidth == .infinity ? x : maxWidth, height: y + rowHeight)
    }
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x: CGFloat = bounds.minX, y: CGFloat = bounds.minY, rowHeight: CGFloat = 0
        for v in subviews {
            let s = v.sizeThatFits(.unspecified)
            if x + s.width > bounds.maxX, x > bounds.minX { x = bounds.minX; y += rowHeight + spacing; rowHeight = 0 }
            v.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += s.width + spacing
            rowHeight = max(rowHeight, s.height)
        }
    }
}

@MainActor
final class ScriptsModel: ObservableObject {
    struct Program: Identifiable {
        let id: String
        let title: String
        let source: String
        let probes: [String]
        let loadedAt: Date
        var loadedAtRelative: String { Self.relativeFormatter.localizedString(for: loadedAt, relativeTo: Date()) }
        var loadedAtAbsolute: String { Self.absoluteFormatter.string(from: loadedAt) }
        private static let relativeFormatter: RelativeDateTimeFormatter = {
            let f = RelativeDateTimeFormatter(); f.unitsStyle = .short; return f
        }()
        private static let absoluteFormatter: DateFormatter = {
            let f = DateFormatter(); f.dateStyle = .none; f.timeStyle = .medium; return f
        }()
    }

    @Published private(set) var programs: [Program] = []

    private var timer: Timer?

    func start() {
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func stop() {
        timer?.invalidate(); timer = nil
    }

    private func refresh() {
        DispatchQueue.global(qos: .userInitiated).async {
            let infos = ESXPCClient.fetchPrograms()
            Task { @MainActor in
                self.programs = infos.map { info in
                    // ID = name (unique within the engine). Title is the
                    // user-supplied program name.
                    Program(id: info.name, title: info.name,
                            source: info.source,
                            probes: info.probes.sorted(),
                            loadedAt: info.loadedAt)
                }.sorted { $0.title < $1.title }
            }
        }
    }

    /// Synthesize a display name from the first non-trivial line of the
    /// source. Programs are submitted by raw text, so this is the best we
    /// can do without a real submission-side label field.
    private static func derivedTitle(from source: String) -> String {
        for raw in source.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("//") {
                let stripped = line.drop(while: { $0 == "/" })
                    .trimmingCharacters(in: .whitespaces)
                if !stripped.isEmpty {
                    // Take everything before the first " — " or end of line.
                    if let dash = stripped.range(of: " — ") {
                        return String(stripped[stripped.startIndex..<dash.lowerBound])
                    }
                    return String(stripped.prefix(60))
                }
            } else if !line.isEmpty {
                return String(line.prefix(60))
            }
        }
        return "program"
    }
}
