import Foundation
import os.log

// TractorES sysext entry point. Unlike TractorNE this is not an NEProvider;
// the sysext is registered as Endpoint Security and stays alive on its XPC
// listener, lazily starting the ESDaemon when the CLI first connects.

private let log = OSLog(subsystem: "com.jacobgroundwater.Tractor.ES", category: "main")

autoreleasepool {
    let reporter = ESReporter()
    reporter.connect()
    os_log("TractorES sysext started", log: log, type: .default)
}

dispatchMain()
