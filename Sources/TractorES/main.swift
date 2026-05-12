import Foundation
import os.log

// TractorES sysext entry point. Unlike TractorNE this is not an NEProvider;
// the sysext is registered as Endpoint Security and stays alive on its XPC
// listener, lazily starting the ESDaemon when the CLI first connects.
//
// IMPORTANT: hold the ESReporter at module scope so the NSXPCListener's
// delegate stays alive for the lifetime of the process. Putting it in an
// autoreleasepool drops it as soon as the pool exits.

private let log = OSLog(subsystem: "com.jacobgroundwater.Tractor.ES", category: "main")

let reporter = ESReporter()
reporter.connect()
os_log("TractorES sysext started", log: log, type: .default)

dispatchMain()
