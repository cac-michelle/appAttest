import XCTest
@testable import AppAttestClient

/// requestHash 的跨語言合約測試。
///
/// ┌──────────────────────────────────────────────────────────────────┐
/// │ 這裡的黃金向量跟後端 tests/Unit/RequestHashTest.php 完全相同。    │
/// │ 任一邊改動導致對不上，兩邊的測試都會紅 —— 這正是我們要的。       │
/// └──────────────────────────────────────────────────────────────────┘
///
/// 不要為了讓測試通過而改期望值。先確認是不是真的要改合約，要改的話
/// 兩邊必須同時改、同時發版。
final class RequestHashTests: XCTestCase {

    /// 對應 PHP 的 `testGoldenVector`。
    func testGoldenVectorMatchesBackend() {
        let challenge = Data(repeating: 0x01, count: 32)

        let hash = RequestHash.compute(
            method: "POST",
            path: "/protected/echo",
            body: Data(#"{"message":"hi"}"#.utf8),
            challenge: challenge
        )

        XCTAssertEqual(hash, "C3jtWGVJfRayYTvpyQXdj283L3wlCMOHXarFy57mAns")
    }

    /// 對應 PHP 的 `testEmptyBodyIsStable`。
    func testEmptyBodyGoldenVectorMatchesBackend() {
        let challenge = Data(repeating: 0x02, count: 32)

        let hash = RequestHash.compute(
            method: "GET",
            path: "/protected/ping",
            body: Data(),
            challenge: challenge
        )

        XCTAssertEqual(hash, "cpfTUEQgLO8Q_i3qFfIGITW7sh571H8yoFBKU5PpKWQ")
    }

    func testMethodIsCaseInsensitive() {
        let challenge = Data(repeating: 0x03, count: 32)

        XCTAssertEqual(
            RequestHash.compute(method: "post", path: "/x", body: Data("b".utf8), challenge: challenge),
            RequestHash.compute(method: "POST", path: "/x", body: Data("b".utf8), challenge: challenge)
        )
    }

    func testEveryInputAffectsTheHash() {
        let challenge = Data(repeating: 0x04, count: 32)
        let base = RequestHash.compute(
            method: "POST", path: "/x", body: Data("b".utf8), challenge: challenge
        )

        // method：攔截者不能把 POST 的簽章拿去用在 DELETE 上
        XCTAssertNotEqual(base, RequestHash.compute(
            method: "DELETE", path: "/x", body: Data("b".utf8), challenge: challenge
        ))

        // path：不能把打到 /x 的簽章轉送到 /admin
        XCTAssertNotEqual(base, RequestHash.compute(
            method: "POST", path: "/admin", body: Data("b".utf8), challenge: challenge
        ))

        // body：這是「竄改內容」被擋下來的根本原因
        XCTAssertNotEqual(base, RequestHash.compute(
            method: "POST", path: "/x", body: Data("c".utf8), challenge: challenge
        ))

        // challenge：同一個請求配不同 challenge 會得到不同 hash
        XCTAssertNotEqual(base, RequestHash.compute(
            method: "POST", path: "/x", body: Data("b".utf8),
            challenge: Data(repeating: 0x05, count: 32)
        ))
    }

    func testOutputIsBase64URLWithoutPadding() {
        let hash = RequestHash.compute(
            method: "POST", path: "/x", body: Data("y".utf8),
            challenge: Data(repeating: 0x06, count: 32)
        )

        XCTAssertEqual(hash.count, 43, "32 bytes 的 base64url 無 padding 應為 43 字元")
        XCTAssertFalse(hash.contains("="))
        XCTAssertFalse(hash.contains("+"))
        XCTAssertFalse(hash.contains("/"))
    }

    // MARK: - path 取法

    /// query string 不能進 requestHash。
    func testPathExcludesQueryString() {
        let url = URL(string: "https://api.example.com/protected/echo?trace=1&lang=zh-TW")!

        XCTAssertEqual(RequestHash.path(of: url), "/protected/echo")
    }

    /// 這個測試守的是一個很難查的跨語言 bug。
    ///
    /// `URL.path` 會把 percent-encoding 解碼（`/a%20b` → `/a b`），但後端
    /// 看到的 `REQUEST_URI` 是**線上實際傳的**那份（未解碼）。用錯的話，
    /// 只有含非 ASCII 或 `%XX` 的 path 會驗不過，其他一切正常。
    func testPathKeepsPercentEncoding() {
        let url = URL(string: "https://api.example.com/protected/%E4%B8%AD%E6%96%87?x=1")!

        XCTAssertEqual(RequestHash.path(of: url), "/protected/%E4%B8%AD%E6%96%87")
        XCTAssertNotEqual(RequestHash.path(of: url), url.path, "不可以用會自動解碼的 URL.path")
    }

    func testPathWithSpacesKeepsEncoding() {
        let url = URL(string: "https://api.example.com/a%20b")!

        XCTAssertEqual(RequestHash.path(of: url), "/a%20b")
    }

    func testEmptyPathBecomesRoot() {
        let url = URL(string: "https://api.example.com")!

        XCTAssertEqual(RequestHash.path(of: url), "/")
    }

    // MARK: - base64url

    func testBase64URLRoundTrip() {
        for length in [1, 2, 3, 31, 32, 64] {
            let original = Data((0..<length).map { _ in UInt8.random(in: 0...255) })
            let encoded = original.base64URLEncodedString()

            XCTAssertEqual(Data.fromBase64URL(encoded), original, "長度 \(length) 應該可以來回轉換")
        }
    }

    /// 後端送來的 challenge 是無 padding 的 base64url，必須解得出來。
    func testDecodesBackendStyleChallenge() {
        let raw = Data(repeating: 0xAB, count: 32)
        let fromBackend = raw.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        XCTAssertEqual(Data.fromBase64URL(fromBackend), raw)
    }
}
