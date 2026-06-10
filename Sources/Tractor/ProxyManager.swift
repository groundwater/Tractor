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

enum ActivationCleanup {
    /// Removes any installed copy of the extension whose team ID is empty
    /// (left behind by pre-codesigned builds). Blocks the calling thread for
    /// up to `timeout`; never call on the main thread.
    static func removeEmptyTeamIDSystemExtension(bundleID: String, timeout: TimeInterval = 5.0) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
        proc.arguments = ["uninstall", "-", bundleID]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
        } catch {
            return
        }

        let deadline = Date().addingTimeInterval(timeout)
        while proc.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if proc.isRunning {
            proc.terminate()
            fputs("Tractor: old empty-team system extension removal did not finish promptly; continuing\n", stderr)
            return
        }
        if proc.terminationStatus == 0 {
            fputs("Tractor: requested removal of old empty-team system extension \(bundleID)\n", stderr)
        }
    }
}

/// Manages Tractor system extension activation and the NE tunnel lifecycle.
final class ProxyManager: NSObject {
    static let esBundleID = "com.jacobgroundwater.Tractor.ES"
    static let neBundleID = "com.jacobgroundwater.Tractor.NE"

    private var activationCompletion: ((Error?) -> Void)?
    private var extensionToActivate: TractorSystemExtension?
    private var activeActivationRequest: OSSystemExtensionRequest?
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
        // Remove any old empty-team-ID copy of the extension before activating,
        // off the main thread — the cleanup waits on systemextensionsctl for up
        // to five seconds.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            ActivationCleanup.removeEmptyTeamIDSystemExtension(bundleID: sysext.rawValue)
            self?.submitActivation(for: sysext)
        }
    }

    private func submitActivation(for sysext: TractorSystemExtension) {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: sysext.rawValue,
            queue: systemExtensionQueue
        )
        request.delegate = self
        activeActivationRequest = request
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

            let tractorManagers = (managers ?? []).filter { manager in
                let provider = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                return provider == Self.neBundleID || manager.localizedDescription == "Tractor Network Monitor"
            }

            // Reuse the existing config if there is one — saving a fresh config
            // triggers a "Tractor would like to add proxy configurations" prompt
            // every time, while updating an existing one doesn't re-prompt. If
            // the existing config has a stale designated requirement (e.g. a
            // cdhash baked in by a previous install), the save below fails and
            // we fall through to recreating it.
            guard let existing = tractorManagers.first else {
                self.createFreshProxy(completion: completion)
                return
            }

            let duplicates = tractorManagers.dropFirst()
            if !duplicates.isEmpty {
                fputs("Tractor: removing \(duplicates.count) duplicate proxy config(s)\n", stderr)
                for manager in duplicates {
                    manager.isEnabled = false
                    (manager.connection as? NETunnelProviderSession)?.stopTunnel()
                    manager.removeFromPreferences { _ in }
                }
            }

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
        extensionToActivate = nil
    }

    private func retryEnableProxy(attemptsLeft: Int) {
        enableProxy { [weak self] error in
            if error == nil {
                self?.activationCompletion?(nil)
                self?.activationCompletion = nil
                self?.extensionToActivate = nil
                return
            }
            if attemptsLeft <= 0 {
                fputs("Tractor: network extension failed: \(error!.localizedDescription)\n", stderr)
                self?.activationCompletion?(error)
                self?.activationCompletion = nil
                self?.extensionToActivate = nil
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                self?.retryEnableProxy(attemptsLeft: attemptsLeft - 1)
            }
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        guard activeActivationRequest === request else {
            return
        }
        fputs("Tractor: sysext failed: \(error.localizedDescription)\n", stderr)
        activationCompletion?(error)
        activationCompletion = nil
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
