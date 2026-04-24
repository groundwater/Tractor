import Foundation
import NetworkExtension
import SystemExtensions

/// Manages the TractorNE system extension lifecycle.
/// Activates the transparent proxy on start, deactivates on stop.
final class ProxyManager: NSObject {
    static let sysextBundleID = "com.jacobgroundwater.Tractor.NE"

    private var activationCompletion: ((Error?) -> Void)?
    private var deactivationCompletion: ((Error?) -> Void)?

    /// Install and activate the system extension + transparent proxy.
    /// Starts the proxy tunnel immediately (fast path), then submits
    /// the sysext activation in the background to update the binary.
    func activate(completion: @escaping (Error?) -> Void) {
        // Start the tunnel immediately — the existing sysext handles it
        enableProxy { [weak self] error in
            if let error = error {
                // No existing config — need full activation first
                fputs("Tractor: no existing proxy config, activating sysext...\n", stderr)
                self?.activationCompletion = completion
                let request = OSSystemExtensionRequest.activationRequest(
                    forExtensionWithIdentifier: Self.sysextBundleID,
                    queue: .main
                )
                request.delegate = self
                OSSystemExtensionManager.shared.submitRequest(request)
                return
            }
            completion(nil)

            // Update the sysext binary in the background (non-blocking)
            self?.activationCompletion = { _ in /* ignore background result */ }
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: Self.sysextBundleID,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    /// Deactivate the system extension.
    func deactivate(completion: @escaping (Error?) -> Void) {
        deactivationCompletion = completion

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.sysextBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Enable the transparent proxy configuration so the OS routes traffic through the sysext.
    private func enableProxy(completion: @escaping (Error?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                completion(error)
                return
            }

            let manager: NETransparentProxyManager
            if let existing = managers?.first {
                manager = existing
            } else {
                manager = NETransparentProxyManager()
            }

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.sysextBundleID
            proto.serverAddress = "localhost"

            manager.protocolConfiguration = proto
            manager.localizedDescription = "Tractor Network Monitor"
            manager.isEnabled = true

            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    completion(saveError)
                    return
                }
                // Load again after save, then start the tunnel
                manager.loadFromPreferences { loadError in
                    if let loadError = loadError {
                        completion(loadError)
                        return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                        fputs("Tractor: proxy tunnel started\n", stderr)
                        completion(nil)
                    } catch {
                        completion(error)
                    }
                }
            }
        }
    }

    /// Disable the transparent proxy so traffic stops flowing through the sysext.
    func disableProxy(completion: @escaping (Error?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                completion(error)
                return
            }
            guard let manager = managers?.first else {
                completion(nil) // nothing to disable
                return
            }
            manager.removeFromPreferences { removeError in
                completion(removeError)
            }
        }
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension ProxyManager: OSSystemExtensionRequestDelegate {

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        fputs("Tractor: sysext activated (result: \(result.rawValue))\n", stderr)

        // After sysext activation, enable the proxy config
        enableProxy { [weak self] error in
            self?.activationCompletion?(error)
            self?.activationCompletion = nil
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        fputs("Tractor: sysext request failed: \(error)\n", stderr)
        activationCompletion?(error)
        activationCompletion = nil
        deactivationCompletion?(error)
        deactivationCompletion = nil
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        fputs("Tractor: sysext needs user approval in System Settings\n", stderr)
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        fputs("Tractor: replacing existing sysext\n", stderr)
        return .replace
    }
}
