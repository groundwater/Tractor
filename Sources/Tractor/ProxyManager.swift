import Foundation
import NetworkExtension
import SystemExtensions

/// Manages the TractorNE system extension lifecycle.
/// Used by the `activate` subcommand to install and start the sysext.
final class ProxyManager: NSObject {
    static let sysextBundleID = "com.jacobgroundwater.Tractor.NE"

    private var activationCompletion: ((Error?) -> Void)?

    /// Activate the system extension and start the proxy tunnel.
    func activate(completion: @escaping (Error?) -> Void) {
        activationCompletion = completion
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.sysextBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func enableProxy(completion: @escaping (Error?) -> Void) {
        fputs("Tractor: enableProxy called\n", stderr)
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                fputs("Tractor: loadAll error: \(error)\n", stderr)
                completion(error)
                return
            }
            fputs("Tractor: found \(managers?.count ?? 0) configs\n", stderr)

            if let existing = managers?.first, existing.protocolConfiguration != nil {
                fputs("Tractor: existing config found, updating...\n", stderr)
                existing.isEnabled = true
                existing.isOnDemandEnabled = false
                existing.saveToPreferences { saveError in
                    if let saveError = saveError {
                        fputs("Tractor: save error: \(saveError)\n", stderr)
                        existing.removeFromPreferences { _ in
                            self.createFreshProxy(completion: completion)
                        }
                        return
                    }
                    existing.loadFromPreferences { _ in
                        fputs("Tractor: starting tunnel...\n", stderr)
                        do {
                            try (existing.connection as? NETunnelProviderSession)?.startTunnel()
                            fputs("Tractor: tunnel started\n", stderr)
                            completion(nil)
                        } catch {
                            fputs("Tractor: startTunnel error: \(error)\n", stderr)
                            completion(error)
                        }
                    }
                }
                return
            }

            fputs("Tractor: no existing config, creating fresh\n", stderr)
            self.createFreshProxy(completion: completion)
        }
    }

    private func createFreshProxy(completion: @escaping (Error?) -> Void) {
        fputs("Tractor: createFreshProxy\n", stderr)
        let manager = NETransparentProxyManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.sysextBundleID
        proto.serverAddress = "localhost"

        manager.protocolConfiguration = proto
        manager.localizedDescription = "Tractor Network Monitor"
        manager.isEnabled = true

        manager.isOnDemandEnabled = false

        manager.saveToPreferences { saveError in
            if let saveError = saveError {
                fputs("Tractor: save error: \(saveError)\n", stderr)
                completion(saveError)
                return
            }
            fputs("Tractor: config saved, loading...\n", stderr)
            manager.loadFromPreferences { loadError in
                if let loadError = loadError {
                    fputs("Tractor: load error: \(loadError)\n", stderr)
                    completion(loadError)
                    return
                }
                fputs("Tractor: starting tunnel...\n", stderr)
                do {
                    try (manager.connection as? NETunnelProviderSession)?.startTunnel()
                    fputs("Tractor: tunnel started\n", stderr)
                    completion(nil)
                } catch {
                    fputs("Tractor: startTunnel error: \(error)\n", stderr)
                    completion(error)
                }
            }
        }
    }

}

extension ProxyManager: OSSystemExtensionRequestDelegate {

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
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
                fputs("Tractor: network extension failed: \(error!.localizedDescription)\n", stderr)
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
        fputs("Tractor: sysext failed: \(error.localizedDescription)\n", stderr)
        activationCompletion?(error)
        activationCompletion = nil
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        fputs("Tractor: approve network extension in System Settings\n", stderr)
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}
