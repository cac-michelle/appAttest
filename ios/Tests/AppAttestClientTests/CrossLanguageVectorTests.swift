import XCTest
@testable import AppAttestClient

/// 跨語言合約測試。
///
/// ┌──────────────────────────────────────────────────────────────────┐
/// │ Fixtures/request-hash-vectors.json 是由**後端的 PHP 實作**產生的。│
/// │ 這個測試驗證 Swift 算出完全相同的結果。                          │
/// └──────────────────────────────────────────────────────────────────┘
///
/// 後端那邊有一個對稱的測試（`CrossLanguageVectorTest.php`）驗證同一份
/// 檔案。所以：
///
///   - 改了 Swift 的算法 → 這個測試紅
///   - 改了 PHP 的算法   → 後端那個測試紅
///   - 想改合約          → 必須重新產生向量檔，兩邊測試同時更新
///
/// 案例涵蓋的邊界包括：空 body、4KB body、含 null byte 的 body、中文與
/// emoji、percent-encoded 的 path、被編碼的斜線。這些正是兩種語言最容易
/// 產生歧異的地方。
final class CrossLanguageVectorTests: XCTestCase {

    private struct Vector: Decodable {
        let method: String
        let path: String
        let bodyBase64: String
        let challengeBase64: String
        let expected: String
    }

    func testAllVectorsFromBackendMatch() throws {
        let vectors = try loadVectors()

        XCTAssertGreaterThan(vectors.count, 50, "向量數量看起來不對，檔案可能沒載到")

        for (index, vector) in vectors.enumerated() {
            let body = vector.bodyBase64.isEmpty
                ? Data()
                : try XCTUnwrap(Data(base64Encoded: vector.bodyBase64), "案例 \(index) 的 body 解不開")
            let challenge = try XCTUnwrap(
                Data(base64Encoded: vector.challengeBase64),
                "案例 \(index) 的 challenge 解不開"
            )

            let actual = RequestHash.compute(
                method: vector.method,
                path: vector.path,
                body: body,
                challenge: challenge
            )

            XCTAssertEqual(
                actual,
                vector.expected,
                """
                案例 \(index) 與後端不一致
                  method = \(vector.method)
                  path   = \(vector.path)
                  body   = \(body.count) bytes
                """
            )
        }
    }

    /// 向量檔裡確實含有會讓兩種語言產生歧異的案例。
    ///
    /// 沒有這個檢查的話，向量檔可能在某次重新產生時退化成一堆無聊的
    /// ASCII 案例，測試依然全綠，但實際上什麼都沒守住。
    func testVectorsCoverTrickyCases() throws {
        let vectors = try loadVectors()

        XCTAssertTrue(
            vectors.contains { $0.path.contains("%") },
            "應該要有 percent-encoded 的 path"
        )
        XCTAssertTrue(
            vectors.contains { $0.bodyBase64.isEmpty },
            "應該要有空 body 的案例"
        )
        XCTAssertTrue(
            vectors.contains { Data(base64Encoded: $0.bodyBase64).map { $0.contains(0x00) } ?? false },
            "應該要有含 null byte 的 body"
        )
        XCTAssertTrue(
            vectors.contains { ($0.bodyBase64.count * 3 / 4) > 1000 },
            "應該要有大 body 的案例"
        )
    }

    private func loadVectors() throws -> [Vector] {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "request-hash-vectors", withExtension: "json"),
            "找不到 request-hash-vectors.json"
        )

        return try JSONDecoder().decode([Vector].self, from: Data(contentsOf: url))
    }
}
