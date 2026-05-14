import AppKit
import Foundation
import SwiftUI

// MARK: - Status types

enum ComponentStatus: Equatable {
    case unknown
    case notInstalled
    case awaitingApproval
    case active
    case error(String)

    var label: String {
        switch self {
        case .unknown: return "checking…"
        case .notInstalled: return "not installed"
        case .awaitingApproval: return "awaiting approval in System Settings"
        case .active: return "active"
        case .error(let msg): return "error: \(msg)"
        }
    }

    var color: Color {
        switch self {
        case .unknown: return .secondary
        case .notInstalled: return .secondary
        case .awaitingApproval: return .orange
        case .active: return .green
        case .error: return .red
        }
    }
}

// MARK: - Status detection

enum SetupStatus {
    static func systemExtensionsRaw() -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/systemextensionsctl")
        proc.arguments = ["list"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
        } catch {
            return ""
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    static func sysextStatus(bundleID: String) -> ComponentStatus {
        let raw = systemExtensionsRaw()
        guard !raw.isEmpty else { return .unknown }
        var sawAny = false
        var sawAwaiting = false
        for line in raw.split(separator: "\n") {
            guard line.contains(bundleID) else { continue }
            sawAny = true
            let lower = line.lowercased()
            // Skip stale terminated/uninstall entries from older versions.
            if lower.contains("terminated") { continue }
            if lower.contains("[activated enabled]") { return .active }
            if lower.contains("waiting for user") { sawAwaiting = true; continue }
            if lower.contains("activated") { return .active }
            sawAwaiting = true
        }
        if sawAwaiting { return .awaitingApproval }
        return sawAny ? .awaitingApproval : .notInstalled
    }

    static func mitmCAStatus() -> ComponentStatus {
        let appGroupID = "group.com.jacobgroundwater.Tractor"
        guard let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) else {
            return .notInstalled
        }
        let certPath = url.appendingPathComponent("mitm-ca.pem").path
        guard FileManager.default.fileExists(atPath: certPath) else { return .notInstalled }
        let trusted = verifyTrust(certPath: certPath)
        return trusted ? .active : .awaitingApproval
    }

    private static func verifyTrust(certPath: String) -> Bool {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        proc.arguments = ["verify-cert", "-c", certPath]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        do {
            try proc.run()
            proc.waitUntilExit()
            return proc.terminationStatus == 0
        } catch {
            return false
        }
    }
}

// MARK: - Setup model

@MainActor
final class SetupModel: ObservableObject {
    @Published var esStatus: ComponentStatus = .unknown
    @Published var neStatus: ComponentStatus = .unknown
    @Published var mitmStatus: ComponentStatus = .unknown

    @Published var esBusy = false
    @Published var neBusy = false
    @Published var mitmBusy = false

    private let proxyManager = ProxyManager()
    private var pollTimer: Timer?

    init() {
        refresh()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 4.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    deinit {
        pollTimer?.invalidate()
    }

    func refresh() {
        Task.detached { [weak self] in
            let es = SetupStatus.sysextStatus(bundleID: "com.jacobgroundwater.Tractor.ES")
            let ne = SetupStatus.sysextStatus(bundleID: "com.jacobgroundwater.Tractor.NE")
            let mitm = SetupStatus.mitmCAStatus()
            await MainActor.run {
                self?.esStatus = es
                self?.neStatus = ne
                self?.mitmStatus = mitm
            }
        }
    }

    func activateES() {
        esBusy = true
        proxyManager.activateES { [weak self] err in
            Task { @MainActor in
                self?.esBusy = false
                if let err = err {
                    self?.esStatus = .error(err.localizedDescription)
                } else {
                    self?.refresh()
                }
            }
        }
    }

    func activateNE() {
        neBusy = true
        proxyManager.activateNetwork { [weak self] err in
            Task { @MainActor in
                self?.neBusy = false
                if let err = err {
                    self?.neStatus = .error(err.localizedDescription)
                } else {
                    self?.refresh()
                }
            }
        }
    }

    func activateMITM() {
        mitmBusy = true
        let executable = Bundle.main.executablePath ?? CommandLine.arguments[0]
        let escaped = executable.replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\\\"\(escaped)\\\" activate certificate-root\" with administrator privileges"

        Task.detached { [weak self] in
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            proc.arguments = ["-e", script]
            let errPipe = Pipe()
            proc.standardError = errPipe
            proc.standardOutput = FileHandle.nullDevice
            var errOutput = ""
            do {
                try proc.run()
                proc.waitUntilExit()
                if proc.terminationStatus != 0 {
                    let data = errPipe.fileHandleForReading.readDataToEndOfFile()
                    errOutput = String(data: data, encoding: .utf8) ?? "exit \(proc.terminationStatus)"
                }
            } catch {
                errOutput = error.localizedDescription
            }
            await MainActor.run {
                self?.mitmBusy = false
                if !errOutput.isEmpty {
                    self?.mitmStatus = .error(errOutput.trimmingCharacters(in: .whitespacesAndNewlines))
                } else {
                    self?.refresh()
                }
            }
        }
    }
}

// MARK: - Setup view

struct SetupView: View {
    @StateObject private var model = SetupModel()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                SetupCard(
                    title: "Endpoint Security extension",
                    explainer: "Required. Watches process tree activity (exec, file, network) for the targets you trace.",
                    status: model.esStatus,
                    busy: model.esBusy,
                    primaryActionTitle: model.esStatus == .active ? "Reactivate" : "Activate",
                    primaryAction: { model.activateES() }
                )
                SetupCard(
                    title: "Network extension",
                    explainer: "Optional. Intercepts TCP/UDP flows for the traced process tree. Enables --net.",
                    status: model.neStatus,
                    busy: model.neBusy,
                    primaryActionTitle: model.neStatus == .active ? "Reactivate" : "Activate",
                    primaryAction: { model.activateNE() }
                )
                SetupCard(
                    title: "MITM root certificate",
                    explainer: "Optional. Installs Tractor's MITM CA into the system trust store so HTTPS traffic can be inspected. Requires admin password.",
                    status: model.mitmStatus,
                    busy: model.mitmBusy,
                    primaryActionTitle: model.mitmStatus == .active ? "Reinstall" : "Install",
                    primaryAction: { model.activateMITM() }
                )
            }
            .padding()
        }
    }
}

private struct SetupCard: View {
    let title: String
    let explainer: String
    let status: ComponentStatus
    let busy: Bool
    let primaryActionTitle: String
    let primaryAction: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title)
                    .font(.headline)
                Spacer()
                statusBadge
            }
            Text(explainer)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                if busy {
                    ProgressView()
                        .controlSize(.small)
                        .padding(.trailing, 4)
                }
                Button(primaryActionTitle, action: primaryAction)
                    .disabled(busy)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color(NSColor.controlBackgroundColor))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.secondary.opacity(0.2), lineWidth: 1)
        )
    }

    private var statusBadge: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(status.color)
                .frame(width: 8, height: 8)
            Text(status.label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}
