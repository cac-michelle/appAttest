import Foundation

/// 一個後端發的 challenge。
public struct Challenge: Equatable, Sendable {
    public let id: String

    /// 原始 32 bytes（已從 base64url 解碼）。算 requestHash 要用這個，
    /// 不是那串 base64 字串。
    public let value: Data

    public init(id: String, value: Data) {
        self.id = id
        self.value = value
    }
}

/// 取得 challenge 的來源。
///
/// ┌──────────────────────────────────────────────────────────────────┐
/// │ 抽成 protocol 是為了留一條退路。                                 │
/// └──────────────────────────────────────────────────────────────────┘
///
/// 目前的合約是「每個受保護請求都要先拿一個新 challenge」，也就是**每次
/// API 呼叫都變成兩個 round trip**。安全性最好，但使用者體感上每個動作
/// 都慢一倍。
///
/// 如果之後量測下來延遲無法接受，替代方案是實作一個會預先抓一批
/// challenge 放著用的 provider。那樣延遲回到正常，代價是 challenge 會在
/// 裝置上存活較久、TTL 得拉長，replay 的時間窗因此變大。
///
/// 換方案時只需要換這個 protocol 的實作，`AttestedClient` 一行都不用改。
public protocol ChallengeProvider: Sendable {
    func nextChallenge() async throws -> Challenge
}

/// 每次都跟後端要一個新 challenge。
public struct ServerChallengeProvider: ChallengeProvider {

    private let baseURL: URL
    private let transport: Transport
    private let platform: String

    public init(baseURL: URL, transport: Transport, platform: String = "ios") {
        self.baseURL = baseURL
        self.transport = transport
        self.platform = platform
    }

    public func nextChallenge() async throws -> Challenge {
        var request = URLRequest(url: baseURL.appendingPathComponent("attestation/challenge"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(["platform": platform])

        let (data, response) = try await transport.send(request)

        guard response.statusCode == 200 else {
            throw AttestationError.invalidServerResponse("challenge 端點回傳 \(response.statusCode)")
        }

        let decoded = try JSONDecoder().decode(ChallengeResponse.self, from: data)

        guard let value = Data.fromBase64URL(decoded.challenge) else {
            throw AttestationError.invalidServerResponse("challenge 不是合法的 base64url")
        }

        return Challenge(id: decoded.challengeId, value: value)
    }

    private struct ChallengeResponse: Decodable {
        let challenge: String
        let challengeId: String
        let expiresAt: String
    }
}
