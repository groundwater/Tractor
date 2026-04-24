import Foundation
import NetworkExtension
import SystemExtensions

/// Manages the TractorNE system extension lifecycle.
/// Activates the transparent proxy on start, deactivates on stop.
final class ProxyManager: NSObject {
    static let sysextBundleID = "com.jacobgroundwater.Tractor.NE"

    private var activationCompletion: ((Error?) -> Void)?
    private var deactivationCompletion: ((Error?) -> Void)?
    private var skipEnableOnActivation = false

    /// Optional callback for status messages (routed to TUI or stderr depending on mode)
    var onStatus: ((String) -> Void)?

    private func log(_ msg: String) {
        if let cb = onStatus {
            cb(msg)
        } else {
            fputs("Tractor: \(msg)\n", stderr)
        }
    }

    /// Install and activate the system extension + transparent proxy.
    func activate(completion: @escaping (Error?) -> Void) {
        enableProxy { [weak self] error in
            if error == nil {
                completion(nil)
                // Update sysext binary in background — skip enableProxy on success
                // since the tunnel is already running
                self?.activationCompletion = { _ in /* already running */ }
                self?.skipEnableOnActivation = true
                let request = OSSystemExtensionRequest.activationRequest(
                    forExtensionWithIdentifier: Self.sysextBundleID,
                    queue: .main
                )
                request.delegate = self
                OSSystemExtensionManager.shared.submitRequest(request)
                return
            }
            self?.log("activating network extension...")
            self?.activationCompletion = completion
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

    private func enableProxy(completion: @escaping (Error?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                completion(error)
                return
            }

            if let existing = managers?.first, existing.protocolConfiguration != nil {
                existing.isEnabled = true
                existing.saveToPreferences { saveError in
                    if saveError != nil {
                        existing.removeFromPreferences { _ in
                            self.createFreshProxy(completion: completion)
                        }
                        return
                    }
                    existing.loadFromPreferences { _ in
                        do {
                            try existing.connection.startVPNTunnel()
                            self.log("network extension active")
                            completion(nil)
                        } catch {
                            completion(error)
                        }
                    }
                }
                return
            }

            self.createFreshProxy(completion: completion)
        }
    }

    private func createFreshProxy(completion: @escaping (Error?) -> Void) {
        let manager = NETransparentProxyManager()

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
            manager.loadFromPreferences { loadError in
                if let loadError = loadError {
                    completion(loadError)
                    return
                }
                do {
                    try manager.connection.startVPNTunnel()
                    self.log("network extension active")
                    completion(nil)
                } catch {
                    completion(error)
                }
            }
        }
    }

    func disableProxy(completion: @escaping (Error?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                completion(error)
                return
            }
            guard let manager = managers?.first else {
                completion(nil)
                return
            }
            manager.removeFromPreferences { removeError in
                completion(removeError)
            }
        }
    }
}

extension ProxyManager: OSSystemExtensionRequestDelegate {

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if skipEnableOnActivation {
            // Background update — tunnel is already running, don't re-enable
            skipEnableOnActivation = false
            activationCompletion?(nil)
            activationCompletion = nil
            return
        }
        retryEnableProxy(attemptsLeft: 5)
    }

    private func retryEnableProxy(attemptsLeft: Int) {
        enableProxy { [weak self] error in
            if error == nil {
                self?.activationCompletion?(nil)
                self?.activationCompletion = nil
                return
            }
            if attemptsLeft <= 0 {
                self?.log("network extension failed: \(error!.localizedDescription)")
                self?.activationCompletion?(error)
                self?.activationCompletion = nil
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                self?.retryEnableProxy(attemptsLeft: attemptsLeft - 1)
            }
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        log("sysext failed: \(error.localizedDescription)")
        activationCompletion?(error)
        activationCompletion = nil
        deactivationCompletion?(error)
        deactivationCompletion = nil
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        log("approve network extension in System Settings")
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}
