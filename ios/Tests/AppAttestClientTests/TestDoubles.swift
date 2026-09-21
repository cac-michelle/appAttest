import CryptoKit
import Foundation
@testable import AppAttestClient

/// 假的 App Attest service。
///
/// 記錄每次呼叫，讓測試可以斷言「只註冊了一次」這類事情。
final class MockAttestationService: AttestationService, @unchecked Sendable {

    private let lock = NSLock()

    var isSupported: Bool
    var generateKeyError: Error?

    private(set) var generateKeyCount = 0
    private(set) var attestCount = 0
    private(set) var assertionCount = 0
    private(set) var lastAssertionClientDataHash: Data?

    init(isSupported: Bool = true) {
        self.isSupported = isSupported
    }

    func generateKey() async throws -> String {
        lock.lock()
        defer { lock.unlock() }

        if let generateKeyError { throw generateKeyError }

        generateKeyCount += 1
        return "mock-key-id-\(generateKeyCount)"
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        attestCount += 1
        return Data("attestation-for-\(keyId)".utf8)
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        assertionCount += 1
        lastAssertionClientDataHash = clientDataHash
        return Data("assertion-for-\(keyId)".utf8)
    }
}

/// 固定回傳同一個 challenge 的 provider，方便測試重算 requestHash。
final class MockChallengeProvider: ChallengeProvider, @unchecked Sendable {

    private let lock = NSLock()
    private var counter = 0

    /// 設定成非 nil 就一直回傳這個值；nil 則每次產生新的。
    var fixed: Challenge?

    private(set) var callCount = 0

    init(fixed: Challenge? = nil) {
        self.fixed = fixed
    }

    func nextChallenge() async throws -> Challenge {
        lock.lock()
        defer { lock.unlock() }

        callCount += 1

        if let fixed { return fixed }

        counter += 1
        return Challenge(
            id: "challenge-\(counter)",
            value: Data(repeating: UInt8(counter % 256), count: 32)
        )
    }
}

/// 可編排回應的假 transport，會記錄所有送出的請求。
final class MockTransport: Transport, @unchecked Sendable {

    struct Stub {
        let status: Int
        let body: Data

        static func json(_ object: [String: Any], status: Int = 200) -> Stub {
            Stub(status: status, body: try! JSONSerialization.data(withJSONObject: object))
        }
    }

    private let lock = NSLock()

    /// path 尾段 → 要回傳的回應序列。用完最後一個就一直重複它。
    private var stubs: [String: [Stub]] = [:]
    private(set) var sentRequests: [URLRequest] = []

    func stub(path: String, with responses: [Stub]) {
        lock.lock()
        defer { lock.unlock() }
        stubs[path] = responses
    }

    func requests(toPath path: String) -> [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return sentRequests.filter { $0.url?.path == path }
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        lock.lock()
        defer { lock.unlock() }

        sentRequests.append(request)

        let path = request.url?.path ?? ""

        guard var queue = stubs[path], !queue.isEmpty else {
            return (Data(), Self.response(for: request, status: 404))
        }

        // 只剩一個時不要移除，讓它成為之後所有呼叫的預設回應。
        let stub = queue.count == 1 ? queue[0] : queue.removeFirst()
        stubs[path] = queue

        return (stub.body, Self.response(for: request, status: stub.status))
    }

    private static func response(for request: URLRequest, status: Int) -> HTTPURLResponse {
        HTTPURLResponse(
            url: request.url ?? URL(string: "https://example.com")!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        )!
    }
}
