import Foundation

/// Mach service name for XPC communication between CLI and sysext.
let tractorXPCServiceName = "com.jacobgroundwater.Tractor.xpc"

/// Protocol the CLI exposes — the sysext calls these to report flow events.
@objc protocol TractorXPCProtocol {
    func reportFlow(
        pid: Int32,
        process: String,
        remoteHost: String,
        remotePort: String,
        proto: String,    // "tcp" or "udp"
        bytesIn: Int64,
        bytesOut: Int64
    )
}
