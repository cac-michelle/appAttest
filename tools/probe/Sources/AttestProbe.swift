import DeviceCheck
import CryptoKit
import SwiftUI
import os

/// App Attest 的真機效能量測。
///
/// 量的是三件事，全部在 Secure Enclave（`attestKey` 還會連 Apple 的伺服器）：
///
///   generateKey()       註冊時一次
///   attestKey()         註冊時一次，**會走網路到 Apple**
///   generateAssertion() **每個受保護請求都會跑一次** ← 最重要的數字
///
/// 這裡不碰我們自己的後端。要回答的問題是「Secure Enclave 簽一次要多久」，
/// 那跟後端無關，加進來只會多出區網、ATS、憑證一堆設置成本。
///
/// App 一啟動就自動跑完，結果同時輸出到畫面和 os_log。
@main
struct AttestProbeApp: App {
    var body: some Scene {
        WindowGroup {
            ProbeView()
        }
    }
}

// MARK: - 量測

struct Sample: Identifiable {
    let id = UUID()
    let label: String
    let milliseconds: [Double]
    let failures: Int

    var min: Double { milliseconds.min() ?? 0 }
    var max: Double { milliseconds.max() ?? 0 }

    var median: Double {
        guard !milliseconds.isEmpty else { return 0 }
        let sorted = milliseconds.sorted()
        return sorted[sorted.count / 2]
    }

    /// 樣本少的時候 p90 意義有限，但至少看得出尾巴。
    var p90: Double {
        guard !milliseconds.isEmpty else { return 0 }
        let sorted = milliseconds.sorted()
        return sorted[Swift.min(Int(Double(sorted.count) * 0.9), sorted.count - 1)]
    }

    var summary: String {
        guard !milliseconds.isEmpty else {
            return "\(label): 全部失敗（\(failures) 次）"
        }
        return String(
            format: "%@: median %.1fms  min %.1f  p90 %.1f  max %.1f  (n=%d, 失敗 %d)",
            label, median, min, p90, max, milliseconds.count, failures
        )
    }
}

@MainActor
final class Probe: ObservableObject {

    private let log = Logger(subsystem: "tw.com.appattest.probe", category: "measurement")

    @Published var lines: [String] = []
    @Published var running = false
    @Published var finished = false

    private let service = DCAppAttestService.shared

    func emit(_ text: String) {
        lines.append(text)
        // os_log 讓 Mac 端可以用 log stream 收，不必盯著手機螢幕。
        log.notice("PROBE \(text, privacy: .public)")
    }

    func run() async {
        guard !running else { return }
        running = true
        defer { running = false; finished = true }

        emit("=== App Attest 真機量測 ===")
        emit("裝置：\(deviceModel())  iOS \(ProcessInfo.processInfo.operatingSystemVersionString)")
        emit("isSupported = \(service.isSupported)")

        guard service.isSupported else {
            emit("這台裝置不支援 App Attest，量測中止")
            return
        }

        // --- generateKey ---
        var keyTimes: [Double] = []
        var keyFailures = 0
        var keyIds: [String] = []

        for i in 1...3 {
            do {
                let (keyId, ms) = try await measure { try await self.generateKey() }
                keyTimes.append(ms)
                keyIds.append(keyId)
                emit(String(format: "generateKey #%d: %.1fms", i, ms))
            } catch {
                keyFailures += 1
                emit("generateKey #\(i) 失敗：\(error.localizedDescription)")
            }
        }

        let keySample = Sample(label: "generateKey", milliseconds: keyTimes, failures: keyFailures)

        // --- attestKey（會走網路到 Apple）---
        var attestTimes: [Double] = []
        var attestFailures = 0

        for (i, keyId) in keyIds.enumerated() {
            let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            let clientDataHash = Data(SHA256.hash(data: challenge))

            do {
                let (_, ms) = try await measure {
                    try await self.attestKey(keyId, clientDataHash: clientDataHash)
                }
                attestTimes.append(ms)
                emit(String(format: "attestKey #%d: %.1fms", i + 1, ms))
            } catch {
                attestFailures += 1
                emit("attestKey #\(i + 1) 失敗：\(error.localizedDescription)")
            }
        }

        let attestSample = Sample(label: "attestKey", milliseconds: attestTimes, failures: attestFailures)

        // --- generateAssertion（最重要）---
        //
        // 每個受保護請求都會跑一次，所以跑 30 次看分布，不只看平均。
        var assertionTimes: [Double] = []
        var assertionFailures = 0

        if let keyId = keyIds.first {
            for i in 1...30 {
                let requestHash = "probe-request-hash-\(i)"
                let clientDataHash = Data(SHA256.hash(data: Data(requestHash.utf8)))

                do {
                    let (_, ms) = try await measure {
                        try await self.generateAssertion(keyId, clientDataHash: clientDataHash)
                    }
                    assertionTimes.append(ms)
                } catch {
                    assertionFailures += 1
                    if assertionFailures <= 3 {
                        emit("generateAssertion #\(i) 失敗：\(error.localizedDescription)")
                    }
                }
            }
        }

        let assertionSample = Sample(
            label: "generateAssertion",
            milliseconds: assertionTimes,
            failures: assertionFailures
        )

        emit("")
        emit("=== 結果 ===")
        emit(keySample.summary)
        emit(attestSample.summary)
        emit(assertionSample.summary)
        emit("")

        if !assertionTimes.isEmpty {
            emit(String(
                format: "每個受保護請求的額外成本：約 %.0fms（Secure Enclave 簽章）",
                assertionSample.median
            ))
            emit("再加上一次拿 challenge 的網路來回。")
        }

        emit("=== 量測結束 ===")
    }

    // MARK: - 計時

    private func measure<T>(_ work: () async throws -> T) async rethrows -> (T, Double) {
        let start = DispatchTime.now().uptimeNanoseconds
        let value = try await work()
        let end = DispatchTime.now().uptimeNanoseconds

        return (value, Double(end - start) / 1_000_000)
    }

    // MARK: - DCAppAttestService 的 async 包裝

    private func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyId, error in
                if let error { continuation.resume(throwing: error) }
                else if let keyId { continuation.resume(returning: keyId) }
                else { continuation.resume(throwing: ProbeError.noResult) }
            }
        }
    }

    private func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                if let error { continuation.resume(throwing: error) }
                else if let attestation { continuation.resume(returning: attestation) }
                else { continuation.resume(throwing: ProbeError.noResult) }
            }
        }
    }

    private func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                if let error { continuation.resume(throwing: error) }
                else if let assertion { continuation.resume(returning: assertion) }
                else { continuation.resume(throwing: ProbeError.noResult) }
            }
        }
    }

    private func deviceModel() -> String {
        var info = utsname()
        uname(&info)

        let machine = withUnsafePointer(to: &info.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) { String(cString: $0) }
        }

        return machine
    }

    enum ProbeError: Error, LocalizedError {
        case noResult

        var errorDescription: String? { "沒有回傳結果也沒有錯誤" }
    }
}

// MARK: - 畫面

struct ProbeView: View {

    @StateObject private var probe = Probe()

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(probe.lines.enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                if probe.running {
                    ProgressView().padding(.top, 8)
                }
            }
            .padding()
        }
        // 自動開跑，不需要使用者點任何東西。
        .task {
            await probe.run()
        }
    }
}
