import Foundation
import NetworkExtension

// Debug: write a breadcrumb so we know the process launched
try? "launched at \(Date())".write(toFile: "/tmp/tractor-ne-launched.txt", atomically: true, encoding: .utf8)

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

try? "dispatchMain at \(Date())".write(toFile: "/tmp/tractor-ne-running.txt", atomically: true, encoding: .utf8)

dispatchMain()
