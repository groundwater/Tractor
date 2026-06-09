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

    private enum RequestPhase {
        case deactivatingBeforeActivation
        case activating
    }

    private var activationCompletion: ((Error?) -> Void)?
    private var extensionToActivate: TractorSystemExtension?
    private var requestPhase: RequestPhase?
    private var activeDeactivationRequest: OSSystemExtensionRequest?
    private var activeActivationRequest: OSSystemExtensionRequest?
    private var deactivationFallback: DispatchWorkItem?
    private let systemExtensionQueue = DispatchQueue(label: "Tractor.system-extension", attributes: .concurrent)

    func activateES(completion: @escaping (Error?) -> Void) {
        activate(.endpointSecurity, completion: completion)
    }

    func activateNetwork(completion: @escaping (Error?) -> Void) {
        activate(.networkExtension, completion: completion)
    }

    private func activate(_ sysext: TractorSystemExtension, completion: @escaping (Error?) -> Void) {
        activationCompletion = completion
        extensionToActivate = sysext
        requestPhase = .activating
        if sysext == .networkExtension {
            removeTractorProxyConfigurations { [weak self] in
                self?.submitActivation(for: sysext)
            }
        } else {
            submitActivation(for: sysext)
        }
    }

    private func submitDeactivation(for sysext: TractorSystemExtension) {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: sysext.rawValue,
            queue: systemExtensionQueue
        )
        request.delegate = self
        activeDeactivationRequest = request
        OSSystemExtensionManager.shared.submitRequest(request)

        let fallback = DispatchWorkItem { [weak self] in
            guard let self,
                  self.requestPhase == .deactivatingBeforeActivation,
                  self.extensionToActivate == sysext,
                  self.activeDeactivationRequest === request else { return }
            fputs("Tractor: deactivation did not finish promptly; continuing with activation\n", stderr)
            self.activeDeactivationRequest = nil
            self.submitActivation(for: sysext)
        }
        deactivationFallback = fallback
        DispatchQueue.main.asyncAfter(deadline: .now() + 10.0, execute: fallback)
    }

    private func submitActivation(for sysext: TractorSystemExtension) {
        deactivationFallback?.cancel()
        deactivationFallback = nil
        activeDeactivationRequest = nil
        requestPhase = .activating
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: sysext.rawValue,
            queue: systemExtensionQueue
        )
        request.delegate = self
        activeActivationRequest = request
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func removeTractorProxyConfigurations(completion: @escaping () -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, _ in
            let matches = (managers ?? []).filter { manager in
                let provider = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                return provider == Self.neBundleID || manager.localizedDescription == "Tractor Network Monitor"
            }
            guard !matches.isEmpty else {
                completion()
                return
            }
            let group = DispatchGroup()
            for manager in matches {
                group.enter()
                manager.isEnabled = false
                (manager.connection as? NETunnelProviderSession)?.stopTunnel()
                manager.removeFromPreferences { _ in group.leave() }
            }
            group.notify(queue: .main, execute: completion)
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

            let tractorManagers = (managers ?? []).filter { manager in
                let provider = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                return provider == Self.neBundleID || manager.localizedDescription == "Tractor Network Monitor"
            }
            guard !tractorManagers.isEmpty else {
                self.createFreshProxy(completion: completion)
                return
            }
            fputs("Tractor: removing \(tractorManagers.count) stale proxy config(s)\n", stderr)
            let group = DispatchGroup()
            for manager in tractorManagers {
                group.enter()
                manager.isEnabled = false
                (manager.connection as? NETunnelProviderSession)?.stopTunnel()
                manager.removeFromPreferences { _ in group.leave() }
            }
            group.notify(queue: .main) {
                self.createFreshProxy(completion: completion)
            }
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
        if activeDeactivationRequest === request, let sysext = extensionToActivate {
            deactivationFallback?.cancel()
            deactivationFallback = nil
            activeDeactivationRequest = nil
            submitActivation(for: sysext)
            return
        }

        guard activeActivationRequest === request else {
            return
        }
        activeActivationRequest = nil
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
        requestPhase = nil
        extensionToActivate = nil
    }

    private func retryEnableProxy(attemptsLeft: Int) {
        enableProxy { [weak self] error in
            if error == nil {
                self?.activationCompletion?(nil)
                self?.activationCompletion = nil
                self?.requestPhase = nil
                self?.extensionToActivate = nil
                return
            }
            if attemptsLeft <= 0 {
                fputs("Tractor: network extension failed: \(error!.localizedDescription)\n", stderr)
                self?.activationCompletion?(error)
                self?.activationCompletion = nil
                self?.requestPhase = nil
                self?.extensionToActivate = nil
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                self?.retryEnableProxy(attemptsLeft: attemptsLeft - 1)
            }
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        if activeDeactivationRequest === request, let sysext = extensionToActivate {
            deactivationFallback?.cancel()
            deactivationFallback = nil
            activeDeactivationRequest = nil
            // A deactivation request can fail when there is no installed copy.
            // Continue with activation; replacement still removes old versions.
            submitActivation(for: sysext)
            return
        }
        guard activeActivationRequest === request else {
            return
        }
        fputs("Tractor: sysext failed: \(error.localizedDescription)\n", stderr)
        activationCompletion?(error)
        activationCompletion = nil
        requestPhase = nil
        extensionToActivate = nil
        activeActivationRequest = nil
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
