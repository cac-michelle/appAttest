import Foundation

/// 受保護請求要帶的 header 名稱。
///
/// 跟後端 `src/Http/AttestationGuard.php` 的常數一一對應。
public enum AttestationHeaders {
    public static let platform = "X-Attest-Platform"
    public static let deviceId = "X-Attest-Device-Id"
    public static let challengeId = "X-Attest-Challenge-Id"
    public static let requestHash = "X-Attest-Request-Hash"

    /// iOS 專用：`generateAssertion()` 的輸出，標準 base64。
    public static let assertion = "X-Attest-Assertion"

    /// Android 專用（後端尚未實作，這裡只是把合約寫完整）。
    public static let integrityToken = "X-Attest-Integrity-Token"
}
