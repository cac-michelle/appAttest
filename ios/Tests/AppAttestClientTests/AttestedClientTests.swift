import CryptoKit
import XCTest
@testable import AppAttestClient

/// `AttestedClient` 的流程測試。
///
/// 這些測試涵蓋的是**不需要真機**就能驗的部分：註冊時機、401 重新註冊、
/// 併發控制、header 內容、requestHash 的正確性。`DCAppAttestService` 的
/// 實際呼叫由 `MockAttestationService` 取代。
final class AttestedClientTests: XCTestCase {

    private let baseURL = URL(string: "https://api.example.com")!
    private let protectedURL = URL(string: "https://api.example.com/protected/echo")!

    private var service: MockAttestationService!
    private var store: InMemoryAttestationStore!
    private var transport: MockTransport!
    private var challenges: MockChallengeProvider!

    override func setUp() {
        super.setUp()

        service = MockAttestationService()
        store = InMemoryAttestationStore()
        transport = MockTransport()
        challenges = MockChallengeProvider()

        stubRegister(deviceId: "device-1")
        stubProtected(status: 200)
    }

    private func makeClient() -> AttestedClient {
        AttestedClient(
            baseURL: baseURL,
            service: service,
            store: store,
            transport: transport,
            challengeProvider: challenges
        )
    }

    private func stubRegister(deviceId: String?, status: Int = 200) {
        transport.stub(path: "/attestation/register", with: [
            .json(["deviceId": deviceId as Any, "status": deviceId == nil ? "rejected" : "trusted"],
                  status: status),
        ])
    }

    private func stubProtected(status: Int, sequence: [Int]? = nil) {
        let statuses = sequence ?? [status]
        transport.stub(path: "/protected/echo", with: statuses.map {
            .json(["ok": true], status: $0)
        })
    }

    private func protectedRequest(body: String = #"{"message":"hi"}"#) -> URLRequest {
        var request = URLRequest(url: protectedURL)
        request.httpMethod = "POST"
        request.httpBody = Data(body.utf8)
        return request
    }

    // MARK: - 註冊

    func testFirstRequestTriggersRegistration() async throws {
        let client = makeClient()

        let (_, response) = try await client.send(protectedRequest())

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(service.generateKeyCount, 1)
        XCTAssertEqual(service.attestCount, 1)
        XCTAssertEqual(try store.load()?.deviceId, "device-1")
    }

    /// 已經註冊過就不該再註冊。
    func testExistingRegistrationIsReused() async throws {
        try store.save(Registration(keyId: "existing-key", deviceId: "existing-device"))

        let client = makeClient()
        _ = try await client.send(protectedRequest())
        _ = try await client.send(protectedRequest())

        XCTAssertEqual(service.generateKeyCount, 0, "不該產生新金鑰")
        XCTAssertTrue(transport.requests(toPath: "/attestation/register").isEmpty)
    }

    /// 後端拒絕註冊 → 丟 registrationRejected。
    func testRejectedRegistrationThrows() async throws {
        stubRegister(deviceId: nil, status: 401)

        let client = makeClient()

        do {
            _ = try await client.send(protectedRequest())
            XCTFail("應該要丟錯")
        } catch AttestationError.registrationRejected {
            // 預期
        }
    }

    /// 不支援 App Attest 的裝置要明確失敗，不能靜默送出沒有憑證的請求。
    func testUnsupportedDeviceThrows() async throws {
        service.isSupported = false

        let client = makeClient()

        do {
            _ = try await client.send(protectedRequest())
            XCTFail("應該要丟錯")
        } catch AttestationError.notSupported {
            // 預期
        }
    }

    /// 註冊失敗後，下一次呼叫要能重新嘗試。
    ///
    /// 如果失敗的 task 被留著，之後每次呼叫都會拿到同一個失敗結果 ——
    /// 即使問題（暫時沒網路）早就排除了，使用者也永遠恢復不了。
    func testFailedRegistrationDoesNotPoisonLaterAttempts() async throws {
        stubRegister(deviceId: nil, status: 401)
        let client = makeClient()

        _ = try? await client.send(protectedRequest())

        // 這次後端恢復正常
        stubRegister(deviceId: "device-recovered")

        let (_, response) = try await client.send(protectedRequest())

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(try store.load()?.deviceId, "device-recovered")
    }

    // MARK: - 併發

    /// App 啟動時常常同時發好幾個請求 —— 只能註冊一次。
    ///
    /// 沒有這個保護的話會產生好幾把金鑰、好幾個 deviceId，而且只有最後
    /// 寫進 store 的那個有用，其餘都是垃圾。
    func testConcurrentRequestsRegisterOnlyOnce() async throws {
        let client = makeClient()
        stubProtected(status: 200)

        try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<10 {
                group.addTask { [self] in
                    let (_, response) = try await client.send(protectedRequest())
                    return response.statusCode
                }
            }

            for try await status in group {
                XCTAssertEqual(status, 200)
            }
        }

        XCTAssertEqual(service.generateKeyCount, 1, "10 個併發請求只該註冊一次")
        XCTAssertEqual(transport.requests(toPath: "/attestation/register").count, 1)
    }

    // MARK: - 401 重新註冊

    /// 401 → 清掉舊註冊 → 重新註冊 → 重試一次。
    ///
    /// 沒有這段的話，後端撤銷裝置或金鑰失效後，使用者會卡在永久 401，
    /// 而且不會知道要重裝 App 才能恢復。
    func testUnauthorizedTriggersReregistrationAndRetry() async throws {
        try store.save(Registration(keyId: "stale-key", deviceId: "stale-device"))
        stubProtected(status: 0, sequence: [401, 200])
        stubRegister(deviceId: "device-fresh")

        let client = makeClient()
        let (_, response) = try await client.send(protectedRequest())

        XCTAssertEqual(response.statusCode, 200, "重試應該要成功")
        XCTAssertEqual(service.generateKeyCount, 1, "應該重新產生金鑰")
        XCTAssertEqual(try store.load()?.deviceId, "device-fresh")
        XCTAssertEqual(transport.requests(toPath: "/protected/echo").count, 2)
    }

    /// 重試後仍然 401 就放棄，不要無限迴圈打爆後端。
    func testStillUnauthorizedAfterRetryThrows() async throws {
        try store.save(Registration(keyId: "stale-key", deviceId: "stale-device"))
        stubProtected(status: 401)
        stubRegister(deviceId: "device-fresh")

        let client = makeClient()

        do {
            _ = try await client.send(protectedRequest())
            XCTFail("應該要丟錯")
        } catch AttestationError.stillRejectedAfterReregistration {
            // 預期
        }

        XCTAssertEqual(
            transport.requests(toPath: "/protected/echo").count, 2,
            "只能重試一次"
        )
    }

    /// 非 401 的錯誤要原樣回傳，不要觸發重新註冊。
    func testServerErrorIsReturnedWithoutReregistration() async throws {
        try store.save(Registration(keyId: "k", deviceId: "d"))
        stubProtected(status: 500)

        let client = makeClient()
        let (_, response) = try await client.send(protectedRequest())

        XCTAssertEqual(response.statusCode, 500)
        XCTAssertEqual(service.generateKeyCount, 0, "500 不該觸發重新註冊")
    }

    // MARK: - header 與 requestHash

    func testAllRequiredHeadersArePresent() async throws {
        let client = makeClient()
        _ = try await client.send(protectedRequest())

        let sent = try XCTUnwrap(transport.requests(toPath: "/protected/echo").first)

        XCTAssertEqual(sent.value(forHTTPHeaderField: AttestationHeaders.platform), "ios")
        XCTAssertEqual(sent.value(forHTTPHeaderField: AttestationHeaders.deviceId), "device-1")
        XCTAssertNotNil(sent.value(forHTTPHeaderField: AttestationHeaders.challengeId))
        XCTAssertNotNil(sent.value(forHTTPHeaderField: AttestationHeaders.requestHash))
        XCTAssertNotNil(sent.value(forHTTPHeaderField: AttestationHeaders.assertion))
    }

    /// 原本的 body 和 method 不可以被改動。
    func testOriginalRequestIsPreserved() async throws {
        let client = makeClient()
        let body = #"{"message":"unchanged"}"#
        _ = try await client.send(protectedRequest(body: body))

        let sent = try XCTUnwrap(transport.requests(toPath: "/protected/echo").first)

        XCTAssertEqual(sent.httpMethod, "POST")
        XCTAssertEqual(sent.httpBody, Data(body.utf8))
    }

    /// 送出的 requestHash 必須等於後端會重算出來的值。
    ///
    /// 這個測試在客戶端模擬後端的動作：拿實際送出的 method / path / body
    /// 加上那次的 challenge，自己算一次，然後跟 header 比對。
    func testRequestHashMatchesWhatBackendWouldRecompute() async throws {
        let challenge = Challenge(id: "fixed-challenge", value: Data(repeating: 0x42, count: 32))
        challenges.fixed = challenge

        let client = makeClient()
        let body = #"{"amount":1}"#
        _ = try await client.send(protectedRequest(body: body))

        let sent = try XCTUnwrap(transport.requests(toPath: "/protected/echo").first)
        let sentHash = try XCTUnwrap(sent.value(forHTTPHeaderField: AttestationHeaders.requestHash))

        let recomputed = RequestHash.compute(
            method: sent.httpMethod ?? "",
            path: RequestHash.path(of: try XCTUnwrap(sent.url)),
            body: sent.httpBody ?? Data(),
            challenge: challenge.value
        )

        XCTAssertEqual(sentHash, recomputed)
    }

    /// assertion 簽的必須是 SHA256(requestHash 字串)，不是別的東西。
    func testAssertionSignsHashOfRequestHashString() async throws {
        let client = makeClient()
        _ = try await client.send(protectedRequest())

        let sent = try XCTUnwrap(transport.requests(toPath: "/protected/echo").first)
        let requestHash = try XCTUnwrap(sent.value(forHTTPHeaderField: AttestationHeaders.requestHash))

        XCTAssertEqual(
            service.lastAssertionClientDataHash,
            Data(SHA256.hash(data: Data(requestHash.utf8)))
        )
    }

    /// 每個請求都要用自己的 challenge（註冊 1 個 + 請求各 1 個）。
    func testEachRequestUsesItsOwnChallenge() async throws {
        let client = makeClient()

        _ = try await client.send(protectedRequest())
        _ = try await client.send(protectedRequest())

        let sent = transport.requests(toPath: "/protected/echo")
        let ids = sent.compactMap { $0.value(forHTTPHeaderField: AttestationHeaders.challengeId) }

        XCTAssertEqual(ids.count, 2)
        XCTAssertNotEqual(ids[0], ids[1], "兩次請求不能共用同一個 challenge")
    }

    // MARK: - reset

    func testResetClearsRegistration() async throws {
        let client = makeClient()
        _ = try await client.send(protectedRequest())

        XCTAssertNotNil(try store.load())

        try await client.reset()

        XCTAssertNil(try store.load())
    }
}
