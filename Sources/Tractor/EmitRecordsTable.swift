import SwiftUI

/// Shared table for `EmitRecord` streams — used by ScriptsView's live output
/// and the Playground emit stream. Scrolls to the newest record as records
/// arrive while `autoScroll` is true.
struct EmitRecordsTable: View {
    let records: [EmitRecord]
    var showProgram: Bool = false
    var autoScroll: Bool = true

    static let timeFormatter: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "HH:mm:ss.SSS"; return f
    }()

    var body: some View {
        ScrollViewReader { proxy in
            Table(records) {
                TableColumn("Time") { r in
                    Text(Self.timeFormatter.string(from: r.time))
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                }
                .width(min: 90, ideal: 100, max: 110)

                if showProgram {
                    TableColumn("Program") { r in
                        Text(r.program)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                    .width(min: 80, ideal: 110, max: 160)
                }

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
            .onChange(of: records.count) { _, _ in
                guard autoScroll, let last = records.last else { return }
                proxy.scrollTo(last.id, anchor: .bottom)
            }
            .overlay {
                if records.isEmpty {
                    ContentUnavailableView {
                        Label("No emits yet", systemImage: "dot.radiowaves.left.and.right")
                    } description: {
                        Text("emit(channel, payload) records from running scripts stream here.")
                    }
                }
            }
        }
    }
}
