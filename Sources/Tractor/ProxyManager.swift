import Foundation
import NetworkExtension
import SystemExtensions

/// Manages both Tractor system extensions' lifecycles (ES + NE).
/// Used by the `activate` subcommand.
final class ProxyManager: NSObject {
    static let esBundleID = "com.jacobgroundwater.Tractor.ES"
    static let neBundleID = "com.jacobgroundwater.Tractor.NE"

    private var activationCompletion: ((Error?) -> Void)?
    /// Tracks which sysexts have finished activation; once both are done we
    /// proceed to enable the NE tunnel and call the completion.
    private var pending: Set<String> = []

    /// Activate both system extensions and start the NE proxy tunnel.
    func activate(completion: @escaping (Error?) -> Void) {
        activationCompletion = completion
        pending = [Self.esBundleID, Self.neBundleID]
        for bundleID in pending {
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: bundleID,
                queue: .main
            )
            request.delegate = self
            OSSystemExtensionManager.shared.submitRequest(request)
        }
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

            // Reuse the existing config if there is one — saving a fresh config
            // triggers a "Tractor would like to add proxy configurations" prompt
            // every time. Updating an existing one doesn't re-prompt. If the
            // existing config has a stale designated requirement (e.g. cdhash
            // baked in by a previous install), the save below fails and we fall
            // through to creating a fresh one.
            if let existing = managers?.first {
                fputs("Tractor: existing config found, updating...\n", stderr)
                existing.isEnabled = true
                existing.isOnDemandEnabled = false
                existing.saveToPreferences { saveError in
                    if let saveError = saveError {
                        fputs("Tractor: update save failed (\(saveError)); recreating\n", stderr)
                        existing.removeFromPreferences { _ in
                            self.createFreshProxy(completion: completion)
                        }
                        return
                    }
                    existing.loadFromPreferences { _ in
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

            self.createFreshProxy(completion: completion)
        }
    }

    private func createFreshProxy(completion: @escaping (Error?) -> Void) {
        fputs("Tractor: createFreshProxy\n", stderr)
        let manager = NETransparentProxyManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.neBundleID
        proto.serverAddress = "Tractor Transparent Proxy"
        proto.providerConfiguration = [:]

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
        pending.remove(request.identifier)
        guard pending.isEmpty else { return }
        // Both sysexts done — now bring up the NE tunnel.
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
