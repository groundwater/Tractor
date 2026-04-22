import Foundation

/// Per-connection network stats from NetworkStatistics.framework (private API)
struct NetConnectionInfo {
    let pid: pid_t
    let remoteAddr: String
    let remotePort: UInt16
    var rxBytes: UInt64 = 0
    var txBytes: UInt64 = 0
    var state: String = ""
    var alive: Bool = true
}

/// Wraps Apple's private NetworkStatistics.framework via dlopen to get
/// per-connection byte counters without spawning subprocesses.
final class NetworkStats {
    private typealias Ptr = UnsafeMutableRawPointer
    private typealias CreateFn = @convention(c) (CFAllocator?, DispatchQueue, @escaping @convention(block) (Ptr) -> Void) -> Ptr?
    private typealias DestroyFn = @convention(c) (Ptr) -> Void
    private typealias AddAllTCPFn = @convention(c) (Ptr) -> Void
    private typealias SetDescBlockFn = @convention(c) (Ptr, @escaping @convention(block) (NSDictionary) -> Void) -> Void
    private typealias SetCountsBlockFn = @convention(c) (Ptr, @escaping @convention(block) (NSDictionary) -> Void) -> Void
    private typealias SetRemovedBlockFn = @convention(c) (Ptr, @escaping @convention(block) () -> Void) -> Void
    private typealias QueryCountsFn = @convention(c) (Ptr) -> Void
    private typealias QueryDescFn = @convention(c) (Ptr) -> Void

    private let createFn: CreateFn
    private let destroyFn: DestroyFn
    private let addAllTCPFn: AddAllTCPFn
    private let setDescBlockFn: SetDescBlockFn
    private let setCountsBlockFn: SetCountsBlockFn
    private let setRemovedBlockFn: SetRemovedBlockFn
    private let queryCountsFn: QueryCountsFn
    private let queryDescFn: QueryDescFn

    private var manager: Ptr?
    private let queue = DispatchQueue(label: "com.jacobgroundwater.tractor.netstats")
    private let lock = NSLock()

    /// Retain ObjC blocks via NSMutableArray so they aren't freed
    private let retainedBlocks = NSMutableArray()

    private var sources: [Ptr] = []
    private var ready = false

    /// Per-source description (pid, addr, port, state)
    private var sourceDesc: [UnsafeRawPointer: (pid: pid_t, addr: String, port: UInt16, state: String)] = [:]
    /// Per-source byte counts
    private var sourceCounts: [UnsafeRawPointer: (rx: UInt64, tx: UInt64)] = [:]

    init?() {
        guard let handle = dlopen("/System/Library/PrivateFrameworks/NetworkStatistics.framework/NetworkStatistics", RTLD_LAZY) else {
            return nil
        }
        guard let c = dlsym(handle, "NStatManagerCreate"),
              let d = dlsym(handle, "NStatManagerDestroy"),
              let t = dlsym(handle, "NStatManagerAddAllTCP"),
              let sb = dlsym(handle, "NStatSourceSetDescriptionBlock"),
              let cb = dlsym(handle, "NStatSourceSetCountsBlock"),
              let rb = dlsym(handle, "NStatSourceSetRemovedBlock"),
              let qc = dlsym(handle, "NStatSourceQueryCounts"),
              let qd = dlsym(handle, "NStatSourceQueryDescription")
        else {
            return nil
        }

        createFn = unsafeBitCast(c, to: CreateFn.self)
        destroyFn = unsafeBitCast(d, to: DestroyFn.self)
        addAllTCPFn = unsafeBitCast(t, to: AddAllTCPFn.self)
        setDescBlockFn = unsafeBitCast(sb, to: SetDescBlockFn.self)
        setCountsBlockFn = unsafeBitCast(cb, to: SetCountsBlockFn.self)
        setRemovedBlockFn = unsafeBitCast(rb, to: SetRemovedBlockFn.self)
        queryCountsFn = unsafeBitCast(qc, to: QueryCountsFn.self)
        queryDescFn = unsafeBitCast(qd, to: QueryDescFn.self)
    }

    func start() {
        let this = self

        let callback: @convention(block) (Ptr) -> Void = { source in
            let sourceKey = UnsafeRawPointer(source)

            let db: @convention(block) (NSDictionary) -> Void = { dict in
                guard let pid = dict["processID"] as? Int32 else { return }
                let state = dict["TCPState"] as? String ?? ""
                var addr = ""
                var port: UInt16 = 0
                if let data = dict["remoteAddress"] as? Data {
                    (addr, port) = this.parseSockaddr(data)
                }
                guard !addr.isEmpty && addr != "0.0.0.0" && addr != "::" else { return }
                this.lock.lock()
                this.sourceDesc[sourceKey] = (pid, addr, port, state)
                this.lock.unlock()
            }

            let cb: @convention(block) (NSDictionary) -> Void = { dict in
                let rx = dict["rxBytes"] as? UInt64 ?? 0
                let tx = dict["txBytes"] as? UInt64 ?? 0
                this.lock.lock()
                this.sourceCounts[sourceKey] = (rx, tx)
                this.lock.unlock()
            }

            let rb: @convention(block) () -> Void = {
                this.lock.lock()
                this.sourceDesc.removeValue(forKey: sourceKey)
                this.sourceCounts.removeValue(forKey: sourceKey)
                this.sources.removeAll { $0 == source }
                this.lock.unlock()
            }

            this.lock.lock()
            this.retainedBlocks.add(db)
            this.retainedBlocks.add(cb)
            this.retainedBlocks.add(rb)
            this.sources.append(source)
            this.lock.unlock()

            this.setDescBlockFn(source, db)
            this.setCountsBlockFn(source, cb)
            this.setRemovedBlockFn(source, rb)
        }

        retainedBlocks.add(callback)

        manager = createFn(kCFAllocatorDefault, queue, callback)
        guard let mgr = manager else { return }
        addAllTCPFn(mgr)

        queue.async {
            this.ready = true
        }
    }

    func stop() {
        if let mgr = manager {
            destroyFn(mgr)
            manager = nil
        }
    }

    /// Trigger a refresh — queries descriptions and counts per source
    func refresh() {
        guard ready else { return }
        // Don't queue if a refresh is already pending
        guard !refreshing else { return }
        refreshing = true
        queue.async { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            let srcs = Array(self.sources)
            self.lock.unlock()
            for src in srcs {
                // Check source is still valid before querying
                self.lock.lock()
                let valid = self.sources.contains(where: { $0 == src })
                self.lock.unlock()
                guard valid else { continue }
                self.queryDescFn(src)
                self.queryCountsFn(src)
            }
            self.refreshing = false
        }
    }
    private var refreshing = false

    /// Get all connections for a specific PID, merging desc + counts
    func connectionsForPid(_ pid: pid_t) -> [NetConnectionInfo] {
        lock.lock()
        defer { lock.unlock() }
        var results: [NetConnectionInfo] = []
        for (key, desc) in sourceDesc {
            guard desc.pid == pid else { continue }
            let counts = sourceCounts[key] ?? (0, 0)
            let alive = desc.state == "Established" || desc.state == "SynSent" || desc.state == "SynReceived"
            results.append(NetConnectionInfo(
                pid: desc.pid,
                remoteAddr: desc.addr,
                remotePort: desc.port,
                rxBytes: counts.rx,
                txBytes: counts.tx,
                state: desc.state,
                alive: alive
            ))
        }
        return results
    }

    /// Parse a raw sockaddr_in/sockaddr_in6 data blob into (addr, port)
    private func parseSockaddr(_ data: Data) -> (String, UInt16) {
        guard data.count >= 4 else { return ("", 0) }

        let family = data[1]  // sa_family is at offset 1 in sockaddr

        if family == UInt8(AF_INET) && data.count >= 8 {
            let port = UInt16(data[2]) << 8 | UInt16(data[3])
            let addrBytes = Array(data[4..<8])
            var addr = in_addr()
            memcpy(&addr, addrBytes, 4)
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
            return (String(cString: buf), port)
        } else if family == UInt8(AF_INET6) && data.count >= 28 {
            let port = UInt16(data[2]) << 8 | UInt16(data[3])
            let addrBytes = Array(data[8..<24])
            var addr = in6_addr()
            memcpy(&addr, addrBytes, 16)
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN))
            return (String(cString: buf), port)
        }

        return ("", 0)
    }
}
