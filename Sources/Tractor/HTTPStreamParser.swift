import Foundation

// MARK: - Traffic chunk (authoritative ordered record)

struct TrafficChunk {
    let direction: TrafficDirection
    let timestamp: Date
    let content: String
}

// MARK: - HTTP Round-Trip (derived view)

struct HTTPRoundTrip {
    var request: String = ""
    var response: String = ""
    var requestLine: String = ""
    var responseLine: String = ""
    var timestamp: Date = Date()
    var responseComplete: Bool = false
}

// MARK: - Traffic direction

enum TrafficDirection {
    case up, down
}

// MARK: - Per-direction parser using CFHTTPMessage

/// Wraps CFHTTPMessage to parse one HTTP message at a time.
/// Handles the sysext 4096-char truncation by detecting new start lines
/// in the data stream even when CFHTTPMessage thinks we're still in the body.
private class MessageParser {
    private var msg: CFHTTPMessage
    private let isRequest: Bool
    private var headersDone = false
    private var rawText = ""
    private var contentLength: Int?
    private var isChunked = false
    private var bodyTextSoFar = ""

    init(isRequest: Bool) {
        self.isRequest = isRequest
        self.msg = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, isRequest).takeRetainedValue()
    }

    struct Result {
        var text: String        // full message text for display (headers + body)
        var startLine: String   // "GET / HTTP/1.1" or "HTTP/1.1 200 OK"
        var isComplete: Bool
    }

    /// Feed a chunk of data. Returns completed messages.
    func feed(_ text: String) -> [Result] {
        var results: [Result] = []
        var input = text

        while !input.isEmpty {
            // TRUNCATION GUARD: if we have headers and are waiting for body,
            // check if the new data starts with an HTTP start line.
            // If so, the previous body was truncated — emit and reset.
            if headersDone, let cl = contentLength, cl > 0, !isChunked {
                let bodyReceived = bodyLength()
                if bodyReceived < cl && startsWithHTTPLine(input) {
                    if let r = extract() { results.append(r) }
                    reset()
                    // Fall through to parse `input` as a new message
                }
            }

            guard let data = input.data(using: .isoLatin1) else { break }

            let accepted = data.withUnsafeBytes { ptr -> Bool in
                guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
                return CFHTTPMessageAppendBytes(msg, base, data.count)
            }

            if !accepted {
                // Message was already complete or data is invalid.
                // Emit current, reset, retry with same input.
                if let r = extract() { results.append(r) }
                reset()

                let retryData = input.data(using: .isoLatin1)!
                let retryOk = retryData.withUnsafeBytes { ptr -> Bool in
                    guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
                    return CFHTTPMessageAppendBytes(msg, base, retryData.count)
                }
                if retryOk {
                    rawText += input
                    input = ""
                    checkHeaders()
                    checkComplete(&results)
                } else {
                    // Can't parse at all — skip to first newline and retry
                    if let nl = input.range(of: "\n") {
                        input = String(input[nl.upperBound...])
                    } else {
                        input = ""
                    }
                }
                continue
            }

            rawText += input
            input = ""

            if !headersDone { checkHeaders() }
            checkComplete(&results)
        }

        return results
    }

    private static let bodilessMethods: Set<String> = ["GET", "HEAD", "OPTIONS", "DELETE", "CONNECT"]

    /// Check if a complete message can be extracted.
    private func checkComplete(_ results: inout [Result]) {
        guard headersDone else { return }

        // Bodiless requests: emit immediately after headers
        if isRequest && contentLength == nil && !isChunked {
            let method = CFHTTPMessageCopyRequestMethod(msg)?.takeRetainedValue() as String? ?? ""
            if Self.bodilessMethods.contains(method) {
                if let r = extract() { results.append(r) }
                reset()
                return
            }
        }

        // Bodyless responses: 1xx, 204, 304
        if !isRequest && contentLength == nil && !isChunked {
            let code = CFHTTPMessageGetResponseStatusCode(msg)
            if (100..<200).contains(code) || code == 204 || code == 304 {
                if let r = extract() { results.append(r) }
                reset()
                return
            }
        }

        if isChunked {
            if rawText.hasSuffix("0\r\n\r\n") || rawText.hasSuffix("0\n\n") || rawText.contains("\r\n0\r\n\r\n") || rawText.contains("\n0\n\n") {
                if let r = extract() { results.append(r) }
                reset()
            }
        } else if let cl = contentLength {
            let bl = bodyLength()
            if bl >= cl {
                // Body is complete. Check for excess bytes (next message).
                let excess = bl - cl
                if excess > 0 {
                    // The raw text has extra bytes belonging to the next message.
                    // We need to trim them and save for next parse.
                    let excessText = String(rawText.suffix(excess))
                    rawText = String(rawText.dropLast(excess))

                    if let r = extract() { results.append(r) }
                    reset()

                    // Feed the excess back
                    let more = feed(excessText)
                    results.append(contentsOf: more)
                } else {
                    if let r = extract() { results.append(r) }
                    reset()
                }
            }
        }
        // No Content-Length, not chunked: can't determine end. Wait for flush() or next message.
    }

    func extract() -> Result? {
        let text = rawText
        guard !text.isEmpty else { return nil }

        let startLine: String
        if isRequest {
            let method = CFHTTPMessageCopyRequestMethod(msg)?.takeRetainedValue() as String? ?? ""
            if !method.isEmpty, let url = CFHTTPMessageCopyRequestURL(msg)?.takeRetainedValue() {
                var path = (url as URL).path
                if path.isEmpty { path = "/" }
                if let q = (url as URL).query { path += "?\(q)" }
                let ver = CFHTTPMessageCopyVersion(msg).takeRetainedValue() as String
                startLine = "\(method) \(path) \(ver)"
            } else {
                // Headers not complete — extract from raw text
                startLine = text.components(separatedBy: "\r\n").first
                    ?? text.components(separatedBy: "\n").first ?? ""
            }
        } else {
            if CFHTTPMessageIsHeaderComplete(msg) {
                let sl = CFHTTPMessageCopyResponseStatusLine(msg)?.takeRetainedValue() as String?
                if let sl = sl, !sl.isEmpty {
                    startLine = sl
                } else {
                    let code = CFHTTPMessageGetResponseStatusCode(msg)
                    let ver = CFHTTPMessageCopyVersion(msg).takeRetainedValue() as String
                    startLine = "\(ver) \(code)"
                }
            } else {
                startLine = text.components(separatedBy: "\r\n").first
                    ?? text.components(separatedBy: "\n").first ?? ""
            }
        }

        let complete: Bool
        if isChunked {
            complete = text.contains("\r\n0\r\n\r\n") || text.hasSuffix("0\r\n\r\n") ||
                       text.contains("\n0\n\n") || text.hasSuffix("0\n\n")
        } else if let cl = contentLength {
            complete = bodyLength() >= cl
        } else {
            complete = CFHTTPMessageIsHeaderComplete(msg)
        }

        return Result(text: text, startLine: startLine, isComplete: complete)
    }

    func reset() {
        msg = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, isRequest).takeRetainedValue()
        headersDone = false
        rawText = ""
        contentLength = nil
        isChunked = false
        bodyTextSoFar = ""
    }

    var hasData: Bool { !rawText.isEmpty }

    private func checkHeaders() {
        guard CFHTTPMessageIsHeaderComplete(msg) else { return }
        headersDone = true
        let h = CFHTTPMessageCopyAllHeaderFields(msg)?.takeRetainedValue() as? [String: String] ?? [:]
        for (k, v) in h {
            let lk = k.lowercased()
            if lk == "transfer-encoding" && v.lowercased().contains("chunked") { isChunked = true }
            if lk == "content-length", let n = Int(v) { contentLength = n }
        }
    }

    private func bodyLength() -> Int {
        if let bodyData = CFHTTPMessageCopyBody(msg)?.takeRetainedValue() as Data? {
            return bodyData.count
        }
        return 0
    }

    private static let methods = ["GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT "]

    private func startsWithHTTPLine(_ text: String) -> Bool {
        if isRequest {
            return Self.methods.contains(where: { text.hasPrefix($0) }) && text.contains("HTTP/")
        } else {
            return text.hasPrefix("HTTP/")
        }
    }
}

// MARK: - HTTP Stream Parser

/// Stores an ordered log of traffic chunks (the source of truth) and derives
/// HTTP round-trips by processing chunks strictly in arrival order.
///
/// Root cause of the old bug: the request MessageParser would hold an incomplete
/// POST body (waiting for Content-Length bytes that never arrive because the
/// sysext truncates). Meanwhile the response parser would emit immediately.
/// Result: response appeared before its request.
///
/// Fix: a direction switch is a message boundary. When we see a DOWN chunk,
/// the preceding UP message is done (the server is already responding).
/// Flush the request parser before feeding the response parser, and vice versa.
class HTTPStreamParser {
    /// Authoritative ordered record of all traffic on this connection.
    private(set) var chunks: [TrafficChunk] = []

    /// Derived round-trips, built incrementally as chunks arrive.
    private(set) var roundTrips: [HTTPRoundTrip] = []

    private var reqParser = MessageParser(isRequest: true)
    private var respParser = MessageParser(isRequest: false)
    private let maxBodySize = 256 * 1024

    private var lastDirection: TrafficDirection?

    func feed(direction: TrafficDirection, content: String) {

        // 1. Store the chunk (authoritative)
        chunks.append(TrafficChunk(direction: direction, timestamp: Date(), content: content))

        // 2. Direction switch = message boundary. Flush the other parser.
        if let last = lastDirection, last != direction {
            if direction == .down {
                // Switching to response — flush any buffered request
                if reqParser.hasData {
                    if let msg = reqParser.extract(), !msg.startLine.isEmpty {
                        emitRequest(msg)
                    }
                    reqParser.reset()
                }
            } else {
                // Switching to request — flush any buffered response
                if respParser.hasData {
                    if let msg = respParser.extract(), !msg.startLine.isEmpty {
                        emitResponse(msg)
                    }
                    respParser.reset()
                }
            }
        }
        lastDirection = direction

        // 3. Feed to the appropriate parser
        if direction == .up {
            for msg in reqParser.feed(content) {
                emitRequest(msg)
            }
        } else {
            let results = respParser.feed(content)
            for msg in results {
                emitResponse(msg)
            }
            // Show partial response headers early
            if results.isEmpty, let partial = respParser.extract(), !partial.startLine.isEmpty {
                showPartialResponse(partial)
            }
        }
    }

    func flush() {
        if reqParser.hasData {
            if let msg = reqParser.extract(), !msg.startLine.isEmpty {
                emitRequest(msg)
            }
            reqParser.reset()
        }
        if respParser.hasData {
            if let msg = respParser.extract(), !msg.startLine.isEmpty {
                emitResponse(msg)
            }
            respParser.reset()
        }

        for i in roundTrips.indices where !roundTrips[i].responseComplete && !roundTrips[i].responseLine.isEmpty {
            roundTrips[i].responseComplete = true
        }
    }

    private func emitRequest(_ msg: MessageParser.Result) {
        var rt = HTTPRoundTrip()
        rt.request = capBody(msg.text)
        rt.requestLine = msg.startLine
        rt.timestamp = Date()
        roundTrips.append(rt)
    }

    private func emitResponse(_ msg: MessageParser.Result) {
        let text = capBody(msg.text)
        // Fill the first round-trip whose response isn't complete yet.
        // This correctly overwrites partial responses from showPartialResponse.
        if let idx = roundTrips.firstIndex(where: { !$0.responseComplete }) {
            roundTrips[idx].response = text
            roundTrips[idx].responseLine = msg.startLine
            roundTrips[idx].responseComplete = msg.isComplete
        } else {
            var rt = HTTPRoundTrip()
            rt.response = text
            rt.responseLine = msg.startLine
            rt.responseComplete = msg.isComplete
            rt.timestamp = Date()
            roundTrips.append(rt)
        }
    }

    private func showPartialResponse(_ msg: MessageParser.Result) {
        if let idx = roundTrips.firstIndex(where: { !$0.responseComplete }) {
            roundTrips[idx].response = msg.text
            roundTrips[idx].responseLine = msg.startLine
            // leave responseComplete = false
        }
    }

    private func capBody(_ text: String) -> String {
        if text.count > maxBodySize {
            return "\n[...truncated...]\n" + String(text.suffix(maxBodySize / 2))
        }
        return text
    }
}
