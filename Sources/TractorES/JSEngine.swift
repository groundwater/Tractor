import Foundation
import JavaScriptCore
import os.log

private let jsLog = OSLog(subsystem: "com.jacobgroundwater.Tractor.ES", category: "js")

// MARK: - Watchdog + helpers (file-private)

private final class WatchdogState {
    private let lock = NSLock()
    private var done = false
    func markDone() { lock.lock(); done = true; lock.unlock() }
    func markFiredIfNotDone() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !done
    }
}

private func sysctlCommName(pid: pid_t) -> String? {
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.size
    let mibCount = UInt32(mib.count)
    let result = mib.withUnsafeMutableBufferPointer { mibPtr -> Int32 in
        sysctl(mibPtr.baseAddress, mibCount, &info, &size, nil, 0)
    }
    guard result == 0, size > 0 else { return nil }
    var commTuple = info.kp_proc.p_comm
    let commCapacity = MemoryLayout.size(ofValue: commTuple)
    let comm: String = withUnsafePointer(to: &commTuple) { ptr in
        ptr.withMemoryRebound(to: CChar.self, capacity: commCapacity) { cstr in
            String(cString: cstr)
        }
    }
    return comm.isEmpty ? nil : comm
}

private func formatLogValue(_ val: JSValue) -> String {
    if val.isString { return val.toString() ?? "" }
    if let ctx = JSContext.current(),
       let json = ctx.objectForKeyedSubscript("JSON"),
       let stringify = json.objectForKeyedSubscript("stringify"),
       let result = stringify.call(withArguments: [val]),
       !result.isUndefined, !result.isNull,
       let s = result.toString() {
        return s
    }
    return val.toString() ?? ""
}

// MARK: - Merge strategy

/// How to combine AUTH verdicts across multiple loaded programs.
/// v1 ships `firstDenyOrPass` only; the enum exists so adding new
/// strategies later doesn't change call sites.
enum MergeStrategy {
    /// Any program denies → deny. All programs see the event (we wait for
    /// the timeout-bounded set of replies). Default and only strategy.
    case firstDenyOrPass
}

// MARK: - Per-program state

/// One loaded JS program. Each has its own `JSVirtualMachine` (so probes
/// can execute concurrently with other programs — JSC serializes JS
/// execution per-VM) and its own dispatch queue.
/// Per-probe execution counters & rolling latency samples. Kept in
/// nanoseconds (mach time converted). Used by `engineStats()`.
struct ProbeStats {
    var dispatches: Int = 0
    var maxLatencyNs: UInt64 = 0
    /// Ring of recent latency samples; oldest dropped past capacity.
    var latencyRing: [UInt64] = []
    static let ringCapacity = 512
}

private final class LoadedProgram {
    let name: String
    let source: String
    let args: [String]
    let loadedAt: Date
    let loaderConnectionID: ObjectIdentifier?

    let vm: JSVirtualMachine
    var context: JSContext
    let queue: DispatchQueue

    /// Probe name → JS callback. Single-program scope.
    var probes: [String: JSValue] = [:]
    /// Active periodic timers from this program's `timer:*` probes.
    var timers: [DispatchSourceTimer] = []
    /// Probe currently executing on this program's queue (for error
    /// attribution by the JSContext.exceptionHandler).
    var activeProbeName: String?
    /// Last exception message seen by the exceptionHandler on this program's
    /// queue. Read (and reset) by loadProgram to detect compile failures —
    /// more reliable than JSContext.exception, which a custom handler
    /// suppresses. Only touched on `queue`, so no extra locking needed.
    var lastException: String?
    /// Per-probe stats. Mutations guarded by JSEngine.statsLock.
    var probeStats: [String: ProbeStats] = [:]

    init(name: String, source: String, args: [String], loaderConnectionID: ObjectIdentifier?) {
        self.name = name
        self.source = source
        self.args = args
        self.loadedAt = Date()
        self.loaderConnectionID = loaderConnectionID
        guard let vm = JSVirtualMachine() else {
            fatalError("JSVirtualMachine() returned nil")
        }
        self.vm = vm
        self.context = JSContext(virtualMachine: vm)!
        self.queue = DispatchQueue(label: "com.jacobgroundwater.Tractor.ES.js.\(name)")
    }
}

// MARK: - JSEngine

/// Multi-program JavaScript host. Each program runs in its own
/// `JSVirtualMachine` for true parallel dispatch; AUTH events fan out to
/// all matching programs in parallel and merge verdicts per the configured
/// MergeStrategy. NOTIFY events fan out without merging.
final class JSEngine {
    /// Hard cap on simultaneously-loaded programs. Above this, `loadProgram`
    /// returns an error. Each program owns a JSVirtualMachine (~MB heap).
    static let maxPrograms = 10

    /// 1s absolute backstop watchdog — kills the sysext if any single JS
    /// invocation runs that long. AUTH probes get a tighter per-event
    /// timeout derived from the kernel deadline.
    static let watchdogTimeoutSeconds: Double = 1.0

    /// Safety margin between our per-program deadline and the kernel
    /// deadline. Below this, kernel auto-allows the event before we can
    /// even collect verdicts.
    private static let kernelDeadlineSafetyMs: Int = 5

    /// Fallback per-program timeout when no kernel deadline is supplied
    /// (NOTIFY-style events). Generous but bounded.
    private static let defaultPerProgramTimeoutMs: Int = 250

    private let orchestrator = DispatchQueue(
        label: "com.jacobgroundwater.Tractor.ES.js.orchestrator",
        attributes: .concurrent
    )
    private let watchdogQueue = DispatchQueue(
        label: "com.jacobgroundwater.Tractor.ES.js.watchdog",
        qos: .userInteractive
    )

    private let programsLock = NSLock()
    private var programs: [String: LoadedProgram] = [:]

    private var mergeStrategy: MergeStrategy = .firstDenyOrPass

    /// Engine-wide stats lock. Guards per-program `probeStats` and the
    /// `deadlineMissesByProbe` map. Held very briefly — single dict
    /// access, no I/O.
    private let statsLock = NSLock()
    private var deadlineMissesByProbe: [String: Int] = [:]
    private let engineStartedAt = Date()

    private weak var reporter: ESReporter?
    private weak var daemon: ESDaemon?

    init(reporter: ESReporter, daemon: ESDaemon) {
        self.reporter = reporter
        self.daemon = daemon
    }

    // MARK: - Program lifecycle

    struct ProgramInfo {
        let name: String
        let source: String
        let probeNames: [String]
        let loadedAt: Date
    }

    /// Load (or replace) a program. Returns nil on success, or an error
    /// string. Replacing happens atomically: old program is torn down
    /// before the new one starts.
    @discardableResult
    func loadProgram(name: String, source: String, args: [String] = [],
                     loaderConnectionID: ObjectIdentifier? = nil) -> String? {
        // Lifecycle around the lock kept short — the actual JS evaluation
        // happens on the new program's own queue.
        programsLock.lock()
        let existed = programs[name] != nil
        if !existed && programs.count >= Self.maxPrograms {
            programsLock.unlock()
            return "too many programs loaded (limit: \(Self.maxPrograms))"
        }
        // Tear down a previous version if reloading.
        if let old = programs[name] {
            old.timers.forEach { $0.cancel() }
            programs.removeValue(forKey: name)
        }
        let program = LoadedProgram(name: name, source: source, args: args,
                                    loaderConnectionID: loaderConnectionID)
        programs[name] = program
        programsLock.unlock()

        // Evaluate on the new program's queue, synchronously so we can
        // return the error to the caller.
        var loadError: String?
        program.queue.sync {
            installGlobals(in: program)
            program.lastException = nil
            runUnderWatchdog(probeName: "\(name):top-level") {
                program.context.evaluateScript(source)
            }
            // The exceptionHandler records into lastException; fall back to
            // context.exception in case evaluation set it directly.
            loadError = program.lastException
                ?? program.context.exception.flatMap { $0.toString() }
        }

        if let err = loadError {
            // Failed load — discard.
            programsLock.lock()
            program.timers.forEach { $0.cancel() }
            programs.removeValue(forKey: name)
            programsLock.unlock()
            os_log("program %{public}@ load failed: %{public}@",
                   log: jsLog, type: .error, name, err)
            return err
        }

        os_log("program %{public}@ loaded (%{public}d probes)",
               log: jsLog, type: .default, name, program.probes.count)
        return nil
    }

    /// Unload by name. No-op if not loaded.
    func unloadProgram(name: String) {
        programsLock.lock()
        guard let prog = programs.removeValue(forKey: name) else {
            programsLock.unlock(); return
        }
        programsLock.unlock()
        prog.queue.sync {
            prog.timers.forEach { $0.cancel() }
            prog.probes.removeAll()
        }
        statsLock.lock(); prog.probeStats.removeAll(); statsLock.unlock()
        os_log("program %{public}@ unloaded", log: jsLog, type: .default, name)
    }

    /// Unload every program whose loader matches `connectionID`. Called
    /// when a CLI XPC connection invalidates.
    func unloadPrograms(loadedBy connectionID: ObjectIdentifier) {
        programsLock.lock()
        let names = programs.compactMap { (k, v) in
            v.loaderConnectionID == connectionID ? k : nil
        }
        programsLock.unlock()
        for n in names { unloadProgram(name: n) }
    }

    func listPrograms() -> [ProgramInfo] {
        programsLock.lock(); defer { programsLock.unlock() }
        return programs.values.map { p in
            ProgramInfo(name: p.name, source: p.source,
                        probeNames: Array(p.probes.keys).sorted(),
                        loadedAt: p.loadedAt)
        }.sorted { $0.name < $1.name }
    }

    // MARK: - AUTH dispatch (parallel fan-out, merged verdicts)

    func handleAuthExec(pid: Int32, ppid: Int32, process: String,
                        argv: [String], cwd: String?,
                        teamID: String?, signingID: String?, isPlatformBinary: Bool,
                        deadline: UInt64) -> Bool {
        return dispatchAuth("es:auth:exec", deadline: deadline, ctx: [
            "pid": pid, "ppid": ppid, "process": process, "argv": argv,
            "cwd": cwd as Any,
            "team_id": teamID as Any,
            "signing_id": signingID as Any,
            "is_platform_binary": isPlatformBinary,
        ])
    }

    func handleAuthCreate(pid: Int32, ppid: Int32, process: String,
                          path: String, deadline: UInt64) -> Bool {
        return dispatchAuth("es:auth:create", deadline: deadline, ctx: [
            "pid": pid, "ppid": ppid, "process": process, "path": path,
        ])
    }

    func handleAuthUnlink(pid: Int32, ppid: Int32, process: String,
                          path: String, deadline: UInt64) -> Bool {
        return dispatchAuth("es:auth:unlink", deadline: deadline, ctx: [
            "pid": pid, "ppid": ppid, "process": process, "path": path,
        ])
    }

    func handleAuthRename(pid: Int32, ppid: Int32, process: String,
                          from: String, to: String, deadline: UInt64) -> Bool {
        return dispatchAuth("es:auth:rename", deadline: deadline, ctx: [
            "pid": pid, "ppid": ppid, "process": process, "from": from, "to": to,
        ])
    }

    /// Fans out to `ne:flow:new` and the protocol-specific
    /// `ne:tcp:new` / `ne:udp:new`. Verdict merges (any-deny-wins).
    func handleNetworkFlow(context: [String: Any]) -> Bool {
        let proto = (context["protocol"] as? String) ?? "tcp"
        let g = dispatchAuth("ne:flow:new", deadline: 0, ctx: context)
        let s = dispatchAuth("ne:\(proto):new", deadline: 0, ctx: context)
        return g || s
    }

    // MARK: - NOTIFY dispatch (parallel fan-out, no merge)

    /// Async dispatch for NOTIFY_EXEC — observe-only exec. Cheaper than
    /// the AUTH variant: no kernel deadline, fans out without merge.
    func handleNotifyExec(pid: Int32, ppid: Int32, process: String, argv: [String],
                          cwd: String?,
                          teamID: String?, signingID: String?, isPlatformBinary: Bool) {
        dispatchNotify("es:notify:exec", ctx: [
            "pid": pid, "ppid": ppid, "process": process, "argv": argv,
            "cwd": cwd as Any,
            "team_id": teamID as Any,
            "signing_id": signingID as Any,
            "is_platform_binary": isPlatformBinary,
        ])
    }

    func handleNotifyWrite(pid: Int32, ppid: Int32, process: String, path: String) {
        dispatchNotify("es:notify:write",
                       ctx: ["pid": pid, "ppid": ppid, "process": process, "path": path])
    }
    func handleNotifyUnlink(pid: Int32, ppid: Int32, process: String, path: String) {
        dispatchNotify("es:notify:unlink",
                       ctx: ["pid": pid, "ppid": ppid, "process": process, "path": path])
    }
    func handleNotifyRename(pid: Int32, ppid: Int32, process: String, from: String, to: String) {
        dispatchNotify("es:notify:rename",
                       ctx: ["pid": pid, "ppid": ppid, "process": process, "from": from, "to": to])
    }
    func handleNotifyExit(pid: Int32, ppid: Int32, process: String) {
        dispatchNotify("es:notify:exit",
                       ctx: ["pid": pid, "ppid": ppid, "process": process])
    }
    func handleNetworkFlowClose(context: [String: Any]) {
        let proto = (context["protocol"] as? String) ?? "tcp"
        dispatchNotify("ne:flow:close", ctx: context)
        dispatchNotify("ne:\(proto):close", ctx: context)
    }
    func handleNetworkFlowBytes(context: [String: Any]) {
        let proto = (context["protocol"] as? String) ?? "tcp"
        dispatchNotify("ne:flow:bytes", ctx: context)
        dispatchNotify("ne:\(proto):bytes", ctx: context)
    }

    // MARK: - Dispatch internals

    /// Snapshot the set of programs that have registered `probeName`.
    /// Lock-free reads inside the fan-out; we copy refs out under the
    /// lock so program teardown can't race the iteration.
    private func programsFor(_ probeName: String) -> [LoadedProgram] {
        programsLock.lock(); defer { programsLock.unlock() }
        return programs.values.filter { $0.probes[probeName] != nil }
    }

    /// Cheap lookup — does *any* loaded program subscribe to this probe
    /// channel. ESDaemon uses this to skip expensive enrichment (argv
    /// extraction, codesigning lookup, cwd syscall, file-path strings)
    /// when no one is listening.
    func hasSubscribers(_ probeName: String) -> Bool {
        programsLock.lock(); defer { programsLock.unlock() }
        for prog in programs.values where prog.probes[probeName] != nil {
            return true
        }
        return false
    }

    /// Parallel AUTH fan-out with merged verdict. Each matching program
    /// runs the probe on its own queue/VM; we wait up to a per-program
    /// timeout for replies and combine using the configured strategy.
    private func dispatchAuth(_ probeName: String, deadline: UInt64,
                              ctx: [String: Any]) -> Bool {
        let matched = programsFor(probeName)
        guard !matched.isEmpty else { return false }

        let timeoutMs = perProgramTimeoutMs(deadline: deadline)
        let group = DispatchGroup()
        let verdictLock = NSLock()
        var verdicts: [Bool] = []

        for prog in matched {
            group.enter()
            prog.queue.async { [weak self] in
                let denied = self?.callProbe(in: prog, probeName: probeName,
                                              ctx: ctx, isAuth: true) ?? false
                verdictLock.lock()
                verdicts.append(denied)
                verdictLock.unlock()
                group.leave()
            }
        }

        // Wait for all programs to return, up to the per-program timeout.
        // Late programs continue running asynchronously — their verdicts
        // simply don't count for this event.
        _ = group.wait(timeout: .now() + .milliseconds(timeoutMs))

        verdictLock.lock()
        let results = verdicts
        verdictLock.unlock()
        checkDeadlineOverrun(probeName: probeName, deadline: deadline)
        return reduceVerdicts(results, with: mergeStrategy)
    }

    /// Parallel NOTIFY fan-out; no return value, no merge.
    private func dispatchNotify(_ probeName: String, ctx: [String: Any]) {
        let matched = programsFor(probeName)
        guard !matched.isEmpty else { return }
        for prog in matched {
            prog.queue.async { [weak self] in
                _ = self?.callProbe(in: prog, probeName: probeName,
                                    ctx: ctx, isAuth: false)
            }
        }
    }

    /// Invoke the probe inside a specific program. Builds the JS ctx,
    /// attaches `deny()` for AUTH probes, runs under the global watchdog.
    /// Returns whether the program denied (always false for NOTIFY).
    private func callProbe(in program: LoadedProgram, probeName: String,
                           ctx: [String: Any], isAuth: Bool) -> Bool {
        guard let cb = program.probes[probeName],
              !cb.isUndefined, !cb.isNull else { return false }
        guard let jsCtx = JSValue(object: ctx, in: program.context) else { return false }
        var denied = false
        if isAuth {
            let denyFn: @convention(block) () -> Void = { denied = true }
            jsCtx.setObject(denyFn, forKeyedSubscript: "deny" as NSString)
        }
        program.activeProbeName = probeName

        // Time the actual JS call (bridging + execution + return).
        let t0 = mach_absolute_time()
        runUnderWatchdog(probeName: "\(program.name):\(probeName)") {
            cb.call(withArguments: [jsCtx])
        }
        let t1 = mach_absolute_time()
        let latencyNs = UInt64(JSEngine.machTicksToNs(t1 - t0))
        recordDispatch(program: program, probeName: probeName, latencyNs: latencyNs)

        program.activeProbeName = nil
        return denied
    }

    private func recordDispatch(program: LoadedProgram, probeName: String, latencyNs: UInt64) {
        statsLock.lock()
        var stats = program.probeStats[probeName] ?? ProbeStats()
        stats.dispatches += 1
        if latencyNs > stats.maxLatencyNs { stats.maxLatencyNs = latencyNs }
        stats.latencyRing.append(latencyNs)
        if stats.latencyRing.count > ProbeStats.ringCapacity {
            stats.latencyRing.removeFirst(stats.latencyRing.count - ProbeStats.ringCapacity)
        }
        program.probeStats[probeName] = stats
        statsLock.unlock()
    }

    /// Apply the merge strategy to collected verdicts. Currently only
    /// `firstDenyOrPass`; extensible enum.
    private func reduceVerdicts(_ verdicts: [Bool], with strategy: MergeStrategy) -> Bool {
        switch strategy {
        case .firstDenyOrPass:
            return verdicts.contains(true)
        }
    }

    /// Per-program timeout for AUTH dispatch. If `deadline` is non-zero
    /// (ES kernel deadline in mach_absolute_time), subtract a safety
    /// margin and convert to milliseconds; else use a sane default.
    private func perProgramTimeoutMs(deadline: UInt64) -> Int {
        guard deadline != 0 else { return Self.defaultPerProgramTimeoutMs }
        let now = mach_absolute_time()
        if deadline <= now { return 0 } // already past — wait briefly anyway
        let remainingTicks = deadline - now
        let remainingMs = Int(Self.machTicksToMs(remainingTicks))
        return max(1, remainingMs - Self.kernelDeadlineSafetyMs)
    }

    private func checkDeadlineOverrun(probeName: String, deadline: UInt64) {
        guard deadline != 0 else { return }
        let now = mach_absolute_time()
        guard now > deadline else { return }
        let overrunMs = Self.machTicksToMs(now - deadline)
        os_log("AUTH probe %{public}@ overran kernel deadline by %.1fms — kernel auto-allowed",
               log: jsLog, type: .error, probeName, overrunMs)
        statsLock.lock()
        deadlineMissesByProbe[probeName, default: 0] += 1
        statsLock.unlock()
    }

    // MARK: - Watchdog + utilities

    private func runUnderWatchdog(probeName: String, _ body: () -> Void) {
        let aborted = WatchdogState()
        let timer = DispatchSource.makeTimerSource(queue: watchdogQueue)
        timer.schedule(deadline: .now() + Self.watchdogTimeoutSeconds,
                       leeway: .milliseconds(20))
        timer.setEventHandler {
            guard aborted.markFiredIfNotDone() else { return }
            os_log("JS deadlock in %{public}@ — terminating sysext after %.1fs",
                   log: jsLog, type: .fault, probeName, Self.watchdogTimeoutSeconds)
            Darwin._exit(137)
        }
        timer.resume()
        body()
        aborted.markDone()
        timer.cancel()
    }

    private static let machTimebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()
    private static func machTicksToMs(_ ticks: UInt64) -> Double {
        machTicksToNs(ticks) / 1_000_000
    }
    private static func machTicksToNs(_ ticks: UInt64) -> Double {
        Double(ticks) * Double(machTimebase.numer) / Double(machTimebase.denom)
    }

    // MARK: - Globals installed into each program's JSContext

    private func installGlobals(in program: LoadedProgram) {
        let ctx = program.context
        let weakProg = WeakBox(program)

        ctx.exceptionHandler = { [weak self] _, exc in
            guard let self = self, let exc = exc,
                  let prog = weakProg.value else { return }
            let message = exc.toString() ?? "<?>"
            // Record for loadProgram's compile check: a custom handler
            // suppresses JSContext.exception, so without this a syntax error
            // would let a broken program "load" with zero probes.
            prog.lastException = message
            let stack = exc.objectForKeyedSubscript("stack")?.toString() ?? ""
            let lineNum = exc.objectForKeyedSubscript("line")?.toNumber() ?? 0
            let probe = prog.activeProbeName ?? "(top-level)"
            os_log("JS exception in %{public}@:%{public}@: %{public}@",
                   log: jsLog, type: .error, prog.name, probe, message)
            self.reporter?.reportEmit(channel: "tractor:error",
                                      program: prog.name,
                                      payload: [
                "probe": probe,
                "message": message,
                "stack": stack,
                "line": lineNum,
            ])
        }

        // probe(name, fn) — register, and schedule a timer if applicable.
        let probeFn: @convention(block) (String, JSValue) -> Void = { [weak self] name, cb in
            guard let self = self, let prog = weakProg.value else { return }
            prog.probes[name] = cb
            if name.hasPrefix("timer:") {
                self.scheduleTimer(probeName: name, in: prog)
            }
        }
        ctx.setObject(probeFn, forKeyedSubscript: "probe" as NSString)

        // emit(channel, obj) — host adds `_program` tag automatically.
        let emitFn: @convention(block) (String, JSValue) -> Void = { [weak self] channel, value in
            guard let self = self, let prog = weakProg.value else { return }
            let payload = (value.toDictionary() as? [String: Any]) ?? [:]
            self.reporter?.reportEmit(channel: channel, program: prog.name, payload: payload)
        }
        ctx.setObject(emitFn, forKeyedSubscript: "emit" as NSString)

        // render(panel, text) — "current state of this panel" (vs emit
        // which is a stream of events). Each call replaces the panel's
        // text. The CLI repaints; the GUI may display the latest in a
        // dedicated area (not implemented yet).
        let renderFn: @convention(block) (String, String) -> Void = { [weak self] panel, text in
            guard let self = self, let prog = weakProg.value else { return }
            self.reporter?.reportPanel(panel: panel, program: prog.name, text: text)
        }
        ctx.setObject(renderFn, forKeyedSubscript: "render" as NSString)

        let logFn: @convention(block) (JSValue) -> Void = { val in
            os_log("JS log: %{public}@", log: jsLog, type: .default, formatLogValue(val))
        }
        ctx.setObject(logFn, forKeyedSubscript: "log" as NSString)

        // loadAverage() — [1m, 5m, 15m]. Cheap, public, unrestricted.
        let loadFn: @convention(block) () -> [Double] = {
            var avg = [Double](repeating: 0, count: 3)
            getloadavg(&avg, 3)
            return avg
        }
        ctx.setObject(loadFn, forKeyedSubscript: "loadAverage" as NSString)

        // ncpu() — logical CPU count. One sysctl, cached after first call.
        let ncpuFn: @convention(block) () -> Int = { JSEngine.cachedNCPU }
        ctx.setObject(ncpuFn, forKeyedSubscript: "ncpu" as NSString)

        // terminalCols() / terminalRows() — CLI-reported size, for
        // adaptive `render(panel, text)` layouts. Defaults to 80x24
        // when no CLI has reported yet.
        let colsFn: @convention(block) () -> Int = { [weak self] in
            self?.currentTerminalCols() ?? 80
        }
        ctx.setObject(colsFn, forKeyedSubscript: "terminalCols" as NSString)
        let rowsFn: @convention(block) () -> Int = { [weak self] in
            self?.currentTerminalRows() ?? 24
        }
        ctx.setObject(rowsFn, forKeyedSubscript: "terminalRows" as NSString)

        // args — string array passed in at load time. Per-program.
        ctx.setObject(program.args, forKeyedSubscript: "args" as NSString)

        // engineStats() — synchronous, sub-microsecond. Returns per-
        // program-per-probe invocation counts + p50/p99 latency. See
        // snapshotEngineStats for the shape.
        let statsFn: @convention(block) () -> [String: Any] = { [weak self] in
            return self?.snapshotEngineStats() ?? [:]
        }
        ctx.setObject(statsFn, forKeyedSubscript: "engineStats" as NSString)

        // getProc(pid) — synchronous single-pid lookup against the ES
        // daemon's in-memory process tree. Returns null if unknown.
        let getProcFn: @convention(block) (Int32) -> Any = { [weak self] pid in
            return self?.daemon?.processTree.proc(pid: pid) ?? NSNull()
        }
        ctx.setObject(getProcFn, forKeyedSubscript: "getProc" as NSString)

        // getAncestry(pid, maxDepth=32) — full parent chain as an array
        // of {pid, ppid, name, exe, started_at_ms}. Walks the in-memory
        // tree; pure pointer-chase, no syscalls.
        let getAncFn: @convention(block) (Int32, Int32) -> [[String: Any]] = { [weak self] pid, depth in
            let max = depth > 0 ? Int(depth) : 32
            return self?.daemon?.processTree.ancestry(pid: pid, maxDepth: max) ?? []
        }
        ctx.setObject(getAncFn, forKeyedSubscript: "getAncestry" as NSString)

        // getAncestryNames(pid, maxDepth=32) — names only. Optimized for
        // the common `arr.includes("curl")` test.
        let getAncNamesFn: @convention(block) (Int32, Int32) -> [String] = { [weak self] pid, depth in
            let max = depth > 0 ? Int(depth) : 32
            return self?.daemon?.processTree.ancestryNames(pid: pid, maxDepth: max) ?? []
        }
        ctx.setObject(getAncNamesFn, forKeyedSubscript: "getAncestryNames" as NSString)

        // listPids() — every live pid in the ES daemon's process tree.
        // Sync, lock-guarded dict iteration. Zero syscalls.
        let listPidsFn: @convention(block) () -> [Int32] = { [weak self] in
            return self?.daemon?.processTree.livePids() ?? []
        }
        ctx.setObject(listPidsFn, forKeyedSubscript: "listPids" as NSString)

        // listProcs() — every entry in the process tree as
        // {pid, ppid, name, exe, started_at_ms, dead_at_ms?}. Sync, no
        // syscalls. Use this for snapshots; pair with getProcStats for
        // anything that needs CPU/mem/threads.
        let listProcsFn: @convention(block) () -> [[String: Any]] = { [weak self] in
            return self?.daemon?.processTree.listProcs() ?? []
        }
        ctx.setObject(listProcsFn, forKeyedSubscript: "listProcs" as NSString)

        // getProcStats(pid) — single per-pid sample: rss/vsize/cpu/threads.
        // One proc_pidinfo syscall. Returns null if the pid is gone.
        let statsForPidFn: @convention(block) (Int32) -> Any = { pid in
            return JSEngine.procStatsSnapshot(pid: pid) ?? NSNull()
        }
        ctx.setObject(statsForPidFn, forKeyedSubscript: "getProcStats" as NSString)

        // getFdPipe(pid, fd) — if (pid, fd) is a kernel pipe, returns
        // {handle, peerhandle}; otherwise null. Lets JS detect pipe
        // patterns (curl|bash) by matching `peerhandle` on one side
        // against `handle` on the other.
        let fdPipeFn: @convention(block) (Int32, Int32) -> Any = { [weak self] pid, fd in
            return self?.daemon?.processTree.fdPipeInfo(pid: pid, fd: fd) ?? NSNull()
        }
        ctx.setObject(fdPipeFn, forKeyedSubscript: "getFdPipe" as NSString)
    }

    /// Snapshot all engine counters into a JS-ready dict. Synchronous,
    /// no I/O — just a brief lock + dict iteration.
    private func snapshotEngineStats() -> [String: Any] {
        // Copy program refs under programsLock so the list doesn't
        // mutate while we iterate.
        programsLock.lock()
        let progRefs = programs.values.sorted { $0.name < $1.name }
        programsLock.unlock()

        statsLock.lock()
        var progArr: [[String: Any]] = []
        for p in progRefs {
            var dispatches: [String: Int] = [:]
            var latency: [String: [String: Int]] = [:]
            for (probeName, stats) in p.probeStats {
                dispatches[probeName] = stats.dispatches
                let sorted = stats.latencyRing.sorted()
                let p50: UInt64 = sorted.isEmpty ? 0 : sorted[sorted.count / 2]
                let p99idx = sorted.isEmpty ? 0 : min(sorted.count - 1,
                                                       Int(Double(sorted.count) * 0.99))
                let p99: UInt64 = sorted.isEmpty ? 0 : sorted[p99idx]
                latency[probeName] = [
                    "p50": Int(p50),
                    "p99": Int(p99),
                    "max": Int(stats.maxLatencyNs),
                    "samples": sorted.count,
                ]
            }
            progArr.append([
                "name": p.name,
                "loaded_at_ms": Int(p.loadedAt.timeIntervalSince1970 * 1000),
                "dispatches": dispatches,
                "latency_ns": latency,
            ])
        }
        var deadlineMisses: [String: Int] = [:]
        for (k, v) in deadlineMissesByProbe { deadlineMisses[k] = v }
        statsLock.unlock()

        return [
            "uptime_ms": Int(Date().timeIntervalSince(engineStartedAt) * 1000),
            "programs": progArr,
            "deadline_misses": deadlineMisses,
        ]
    }

    private static let cachedNCPU: Int = {
        var n: Int32 = 0
        var size = MemoryLayout<Int32>.size
        sysctlbyname("hw.logicalcpu", &n, &size, nil, 0)
        return n > 0 ? Int(n) : 1
    }()

    // MARK: - Terminal-size hint from the CLI

    /// Latest terminal size reported by a connected CLI. Stored globally
    /// (last-writer-wins). JS reads via `terminalCols()` / `terminalRows()`.
    /// Defaults to 80x24 — sane fallback when no CLI has reported yet.
    private let termSizeLock = NSLock()
    private var termCols: Int = 80
    private var termRows: Int = 24

    func setTerminalSize(cols: Int, rows: Int) {
        termSizeLock.lock()
        if cols > 0 { termCols = cols }
        if rows > 0 { termRows = rows }
        termSizeLock.unlock()
    }
    func currentTerminalCols() -> Int {
        termSizeLock.lock(); defer { termSizeLock.unlock() }
        return termCols
    }
    func currentTerminalRows() -> Int {
        termSizeLock.lock(); defer { termSizeLock.unlock() }
        return termRows
    }

    private func scheduleTimer(probeName: String, in program: LoadedProgram) {
        let spec = probeName.dropFirst("timer:".count)
        let ms: Int
        if spec.hasSuffix("ms"), let n = Int(spec.dropLast(2)), n > 0 { ms = n }
        else if spec.hasSuffix("s"), let n = Int(spec.dropLast(1)), n > 0 { ms = n * 1000 }
        else {
            os_log("ignoring malformed timer probe: %{public}@", log: jsLog, type: .error, probeName)
            return
        }
        let t = DispatchSource.makeTimerSource(queue: program.queue)
        t.schedule(deadline: .now() + .milliseconds(ms), repeating: .milliseconds(ms))
        let weakProg = WeakBox(program)
        t.setEventHandler { [weak self] in
            guard let self = self, let prog = weakProg.value else { return }
            guard let cb = prog.probes[probeName], !cb.isUndefined, !cb.isNull else { return }
            prog.activeProbeName = probeName
            let t0 = mach_absolute_time()
            self.runUnderWatchdog(probeName: "\(prog.name):\(probeName)") {
                cb.call(withArguments: [[String: Any]()])
            }
            let t1 = mach_absolute_time()
            let latencyNs = UInt64(JSEngine.machTicksToNs(t1 &- t0))
            self.recordDispatch(program: prog, probeName: probeName, latencyNs: latencyNs)
            prog.activeProbeName = nil
        }
        t.resume()
        program.timers.append(t)
    }

    // MARK: - Per-pid stats (single proc_pidinfo syscall)

    /// Single-pid CPU/mem/threads sample. JS gets this via getProcStats(pid)
    /// — caller iterates if they want a sweep. Returns nil if the pid is
    /// gone or proc_pidinfo refuses (e.g., reaped between calls).
    static func procStatsSnapshot(pid: Int32) -> [String: Any]? {
        guard pid > 0 else { return nil }
        var all = proc_taskallinfo()
        let allSize = Int32(MemoryLayout<proc_taskallinfo>.size)
        let s = proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &all, allSize)
        guard s == allSize else { return nil }
        let comm = withUnsafeBytes(of: all.pbsd.pbi_comm) { raw in
            String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
        }
        return [
            "pid":           Int(pid),
            "ppid":          Int(all.pbsd.pbi_ppid),
            "user":          Int(all.pbsd.pbi_uid),
            "comm":          comm,
            "rss_bytes":     Int(all.ptinfo.pti_resident_size),
            "vsize_bytes":   Int(all.ptinfo.pti_virtual_size),
            // pti_total_user/system are in mach ticks — convert to ns so
            // callers can do `cpu_ns / 1e9` without knowing host timebase.
            "cpu_user_ns":   Int(machTicksToNs(all.ptinfo.pti_total_user)),
            "cpu_system_ns": Int(machTicksToNs(all.ptinfo.pti_total_system)),
            "threads":       Int(all.ptinfo.pti_threadnum),
        ]
    }

}

/// Weak-reference helper. The block-based JSValue globals capture the
/// program by reference; without a weak wrapper the JSValue → block →
/// LoadedProgram → JSContext chain would cycle.
private final class WeakBox<T: AnyObject> {
    weak var value: T?
    init(_ v: T) { self.value = v }
}
