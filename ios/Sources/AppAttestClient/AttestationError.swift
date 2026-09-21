import Foundation

/// 客戶端這一側可能出現的錯誤。
public enum AttestationError: Error, LocalizedError {

    /// 這台裝置不支援 App Attest（模擬器、越獄、系統太舊）。
    case notSupported

    /// `DCAppAttestService` 回報錯誤。
    ///
    /// 最需要注意的是 `DCError.invalidKey`：金鑰已失效，必須重新註冊。
    /// `AttestedClient` 會自動處理這個情況。
    case deviceCheckFailed(Error)

    /// completion handler 的值和錯誤同時是 nil —— 理論上不該發生，
    /// 但不明確處理的話呼叫端會永遠卡住。
    case deviceCheckReturnedNothing

    /// 後端在註冊階段拒絕了這台裝置。
    ///
    /// 後端不會說明原因（那是刻意的，避免變成攻擊者的 oracle），
    /// 要查原因請看 server log。
    case registrationRejected

    /// 重新註冊後仍然被拒。不再重試，避免無限迴圈。
    case stillRejectedAfterReregistration

    /// 後端回應的格式不符預期。
    case invalidServerResponse(String)

    /// 請求缺少必要資訊（例如沒有 URL）。
    case invalidRequest(String)

    public var errorDescription: String? {
        switch self {
        case .notSupported:
            return "這台裝置不支援 App Attest（模擬器或系統版本過舊）"
        case .deviceCheckFailed(let error):
            return "App Attest 失敗：\(error.localizedDescription)"
        case .deviceCheckReturnedNothing:
            return "App Attest 沒有回傳結果也沒有回報錯誤"
        case .registrationRejected:
            return "後端拒絕了這台裝置的註冊"
        case .stillRejectedAfterReregistration:
            return "重新註冊後仍被拒絕"
        case .invalidServerResponse(let detail):
            return "後端回應格式不符預期：\(detail)"
        case .invalidRequest(let detail):
            return "請求不合法：\(detail)"
        }
    }
}
