import Foundation

/// Shared ISO-8601 timestamp formatting for trace records — one formatter,
/// one format, so SQLite rows, JSON event output, and summary parsing agree.
enum TraceTimestamp {
    static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    static func now() -> String {
        formatter.string(from: Date())
    }
}
