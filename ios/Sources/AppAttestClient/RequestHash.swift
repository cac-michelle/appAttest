import CryptoKit
import Foundation

/// 把一個 HTTP 請求綁定到一個 challenge 上。
///
/// ┌─────────────────────────────────────────────────────────────────┐
/// │ 這段必須跟後端的 src/RequestHash.php 逐位元組完全一致。          │
/// │ 改這裡就等於改合約，兩邊必須同時改、同時發版。                  │
/// └─────────────────────────────────────────────────────────────────┘
///
/// 算法：
///
///     requestHash = base64url_nopad(
///         SHA256( METHOD ‖ "\n" ‖ path ‖ "\n" ‖ SHA256(body) ‖ "\n" ‖ challenge )
///     )
///
/// - `SHA256(body)` 是 **32 bytes 的原始位元組**，不是 hex 字串
/// - `challenge` 是 server 給的**原始 32 bytes**，不是 base64 字串
/// - `path` 不含 query string，而且要用 **percent-encoded** 的形式（見下）
///
/// `RequestHashTests` 裡的黃金測試向量跟 PHP 端 `RequestHashTest` 用的是
/// 同一組值。兩邊任一方改動導致向量對不上，測試就會紅。
public enum RequestHash {

    /// 算出一個請求的 requestHash。
    ///
    /// - Parameters:
    ///   - method: HTTP method，大小寫不拘（內部會轉大寫）
    ///   - path: URL path，不含 query string，percent-encoded
    ///   - body: 原始 request body（沒有 body 就傳 `Data()`）
    ///   - challenge: server 發的原始 32 bytes
    public static func compute(method: String, path: String, body: Data, challenge: Data) -> String {
        var payload = Data()

        payload.append(Data(method.uppercased().utf8))
        payload.append(0x0A)                                 // "\n"
        payload.append(Data(path.utf8))
        payload.append(0x0A)
        payload.append(Data(SHA256.hash(data: body)))        // 原始 32 bytes，不是 hex
        payload.append(0x0A)
        payload.append(challenge)                            // 原始 32 bytes，不是 base64

        return Data(SHA256.hash(data: payload)).base64URLEncodedString()
    }

    /// 從 `URLRequest` 取出算 requestHash 需要的 path。
    ///
    /// === 這裡有一個很容易踩的跨語言陷阱 ===
    ///
    /// `URL.path` 回傳的是 **percent-decoding 之後**的字串：
    ///
    ///     URL(string: "https://x.com/a%20b")!.path        // "/a b"    ← 解碼過
    ///     components.percentEncodedPath                    // "/a%20b"  ← 線上實際傳的
    ///
    /// 後端看到的是 `REQUEST_URI`，也就是**線上實際傳的那份**（未解碼）。
    /// 所以這裡必須用 `percentEncodedPath`，否則只要 path 含有非 ASCII 字元
    /// 或 `%XX`，兩邊算出的 hash 就會不同 —— 而且只有那些特定的 URL 會壞，
    /// 其他一切正常，是最難查的那種 bug。
    ///
    /// 沒有 path 時回傳 `"/"`，與後端行為一致。
    public static func path(of url: URL) -> String {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return "/"
        }

        let path = components.percentEncodedPath

        return path.isEmpty ? "/" : path
    }
}

extension Data {
    /// base64url（RFC 4648 §5），無 padding。
    ///
    /// 跟一般 base64 的差別只有：`+` → `-`、`/` → `_`，並去掉結尾的 `=`。
    /// 這樣才能安全地放進 HTTP header 和 URL。
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// 解 base64url。輸入不合法時回傳 `nil`。
    static func fromBase64URL(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // 補回 base64 需要的 padding。
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }

        return Data(base64Encoded: base64)
    }
}
