import Foundation

#if canImport(DeviceCheck)
// @preconcurrency：DeviceCheck 還沒標註 Sendable，沒有這個標記在
// Swift 6 語言模式下會變成錯誤。
@preconcurrency import DeviceCheck
#endif

/// 包住 `DCAppAttestService` 的介面。
///
/// 抽成 protocol 有兩個實際理由，不是為了抽象而抽象：
///
/// 1. **模擬器上 App Attest 不存在**。`DCAppAttestService.isSupported` 在
///    模擬器一律是 `false`，沒有替代實作你就沒辦法在模擬器開發任何會經過
///    受保護 API 的畫面。
///
/// 2. **測試**。註冊流程、401 重試、併發控制這些邏輯都能用假的實作測到，
///    不需要真機。
public protocol AttestationService: Sendable {
    /// 這台裝置支不支援 App Attest。模擬器、越獄裝置、太舊的系統都會是 false。
    var isSupported: Bool { get }

    /// 產生一把新的金鑰，回傳 keyId（base64 字串）。私鑰留在 Secure Enclave，
    /// 任何人都拿不出來。
    func generateKey() async throws -> String

    /// 為金鑰取得 attestation。
    /// - Parameter clientDataHash: `SHA256(challenge)`
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data

    /// 為一個請求簽 assertion。
    /// - Parameter clientDataHash: `SHA256(requestHash 字串)`
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

#if canImport(DeviceCheck)

/// 真正的實作，直接轉呼叫 `DCAppAttestService`。
///
/// 這個型別**只能在真機上運作**。`DCAppAttestService` 的 API 是
/// completion handler 形式，這裡用 continuation 橋接成 async。
public struct DeviceCheckAttestationService: AttestationService {

    public init() {}

    /// 直接用 `.shared`，不把它存成屬性。
    ///
    /// 一來 `DCAppAttestService` 沒有標 `Sendable`，存起來會讓這個 struct
    /// 在 Swift 6 模式下無法安全地跨 actor 傳遞；二來測試替身該從
    /// `AttestationService` 這個 protocol 換掉，不是從這裡注入。
    private var service: DCAppAttestService { .shared }

    public var isSupported: Bool {
        service.isSupported
    }

    public func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyId, error in
                Self.resume(continuation, value: keyId, error: error)
            }
        }
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                Self.resume(continuation, value: attestation, error: error)
            }
        }
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                Self.resume(continuation, value: assertion, error: error)
            }
        }
    }

    /// 把 (值, 錯誤) 這組 completion 參數轉成 continuation 的結果。
    ///
    /// 特別注意「兩個都是 nil」這個情況：continuation 沒有被 resume 的話，
    /// 呼叫端會永遠卡住。所以這裡明確補上一個錯誤，而不是假設不會發生。
    private static func resume<T>(
        _ continuation: CheckedContinuation<T, Error>,
        value: T?,
        error: Error?
    ) {
        if let error {
            continuation.resume(throwing: AttestationError.deviceCheckFailed(error))
        } else if let value {
            continuation.resume(returning: value)
        } else {
            continuation.resume(throwing: AttestationError.deviceCheckReturnedNothing)
        }
    }
}

#endif

#if DEBUG

/// 模擬器/單元測試用的假實作。
///
/// ┌──────────────────────────────────────────────────────────────────┐
/// │ 整個型別包在 `#if DEBUG` 裡 —— release build 裡它根本不存在。    │
/// └──────────────────────────────────────────────────────────────────┘
///
/// 這不是潔癖。如果它能被 release build 編進去，那麼某天某個人為了讓
/// 模擬器跑得動而在某處留下一行 fallback，整套 attestation 就等於關掉了，
/// 而且沒有任何外顯症狀 —— App 一切正常，只是不再受保護。
///
/// 讓它在編譯層面就不存在，這種事就不可能發生。
///
/// 它產生的 attestation 和 assertion 都是假的，**後端一定會拒絕**。用途是
/// 讓你在模擬器上能跑到「送出請求」為止，而不是讓驗證通過。
public struct StubAttestationService: AttestationService {

    public init() {}

    public var isSupported: Bool { true }

    public func generateKey() async throws -> String {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        Data("stub-attestation-will-be-rejected-by-server".utf8) + clientDataHash
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        Data("stub-assertion-will-be-rejected-by-server".utf8) + clientDataHash
    }
}

#endif
