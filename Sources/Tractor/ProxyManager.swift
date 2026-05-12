import Foundation
import NetworkExtension
import SystemExtensions

enum TractorSystemExtension: String {
    case endpointSecurity = "com.jacobgroundwater.Tractor.ES"
    case networkExtension = "com.jacobgroundwater.Tractor.NE"

    var approvalName: String {
        switch self {
        case .endpointSecurity:
            return "Endpoint Security extension"
        case .networkExtension:
            return "network extension"
        }
    }
}

/// Manages Tractor system extension activation and the NE tunnel lifecycle.
final class ProxyManager: NSObject {
    static let esBundleID = "com.jacobgroundwater.Tractor.ES"
    static let neBundleID = "com.jacobgroundwater.Tractor.NE"

    private var activationCompletion: ((Error?) -> Void)?
    private var extensionToActivate: TractorSystemExtension?

    func activateES(completion: @escaping (Error?) -> Void) {
        activate(.endpointSecurity, completion: completion)
    }

    func activateNetwork(completion: @escaping (Error?) -> Void) {
        activate(.networkExtension, completion: completion)
    }

    private func activate(_ sysext: TractorSystemExtension, completion: @escaping (Error?) -> Void) {
        activationCompletion = completion
        extensionToActivate = sysext
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: sysext.rawValue,
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
        guard let sysext = extensionToActivate else {
            activationCompletion?(nil)
            activationCompletion = nil
            return
        }
        if sysext == .networkExtension {
            retryEnableProxy(attemptsLeft: 5)
            return
        }
        activationCompletion?(nil)
        activationCompletion = nil
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
        let name = extensionToActivate?.approvalName ?? "system extension"
        fputs("Tractor: approve \(name) in System Settings\n", stderr)
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}
