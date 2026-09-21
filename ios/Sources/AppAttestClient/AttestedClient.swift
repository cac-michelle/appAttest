import CryptoKit
import Foundation

/// 帶 App Attest 憑證發送受保護請求的客戶端。
///
/// 用法只有一個方法：
///
/// ```swift
/// let client = AttestedClient(
///     baseURL: URL(string: "https://api.example.com")!,
///     service: DeviceCheckAttestationService(),
///     store: KeychainAttestationStore(service: Bundle.main.bundleIdentifier!)
/// )
///
/// var request = URLRequest(url: URL(string: "https://api.example.com/protected/echo")!)
/// request.httpMethod = "POST"
/// request.httpBody = Data(#"{"message":"hi"}"#.utf8)
///
/// let (data, response) = try await client.send(request)
/// ```
///
/// 它負責：確認已註冊（沒有就註冊）→ 取 challenge → 算 requestHash →
/// 簽 assertion → 裝 header → 送出 → 必要時重新註冊並重試一次。
///
/// === 為什麼是 actor ===
///
/// App 啟動時經常同時發好幾個請求。如果不做序列化，每一個都會發現
/// 「還沒註冊」然後各自跑一次註冊流程 —— 產生好幾把金鑰、好幾個
/// deviceId，而且只有最後寫進 Keychain 的那個有用。actor 加上共用的
/// in-flight task 確保同一時間只有一次註冊在跑。
public actor AttestedClient {

    private let baseURL: URL
    private let service: AttestationService
    private let store: AttestationStore
    private let transport: Transport
    private let challengeProvider: ChallengeProvider
    private let platform: String

    /// 正在進行中的註冊。多個併發呼叫共用同一個 task，不會重複註冊。
    private var registrationTask: Task<Registration, Error>?

    public init(
        baseURL: URL,
        service: AttestationService,
        store: AttestationStore,
        transport: Transport = URLSessionTransport(),
        challengeProvider: ChallengeProvider? = nil,
        platform: String = "ios"
    ) {
        self.baseURL = baseURL
        self.service = service
        self.store = store
        self.transport = transport
        self.challengeProvider = challengeProvider
            ?? ServerChallengeProvider(baseURL: baseURL, transport: transport, platform: platform)
        self.platform = platform
    }

    /// 送出一個受保護請求。
    ///
    /// 收到 401 時會清掉本地註冊、重新註冊，然後**重試一次**。
    ///
    /// 這段不是可有可無的：後端可能撤銷裝置，iOS 也可能讓金鑰失效
    /// （系統還原、`DCError.invalidKey`）。沒有這個機制的話，使用者會卡在
    /// 永久 401，唯一的解法是重裝 App —— 而他們不會知道要這麼做。
    ///
    /// 只重試一次。重試後還是 401 就往上拋，避免無限迴圈打爆後端。
    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let registration = try await ensureRegistered()
        let (data, response) = try await attempt(request, using: registration)

        guard response.statusCode == 401 else {
            return (data, response)
        }

        // 401：本地這份註冊已經不被接受了，丟掉重來。
        try? store.clear()
        registrationTask = nil

        let fresh = try await ensureRegistered()
        let (retryData, retryResponse) = try await attempt(request, using: fresh)

        guard retryResponse.statusCode != 401 else {
            throw AttestationError.stillRejectedAfterReregistration
        }

        return (retryData, retryResponse)
    }

    /// 丟棄目前的註冊，下一次請求會重新註冊。
    ///
    /// 一般情況不需要手動呼叫（401 會自動處理）。登出時清掉是合理的用法。
    public func reset() throws {
        registrationTask = nil
        try store.clear()
    }

    // MARK: - 註冊

    private func ensureRegistered() async throws -> Registration {
        if let existing = try store.load() {
            return existing
        }

        // 已經有一個註冊在跑就等它，不要再開一個。
        if let inFlight = registrationTask {
            return try await inFlight.value
        }

        let task = Task { try await performRegistration() }
        registrationTask = task

        do {
            let registration = try await task.value
            registrationTask = nil
            return registration
        } catch {
            // 失敗要把 task 清掉，否則之後每次呼叫都會拿到同一個失敗結果，
            // 即使問題（例如暫時沒網路）早就排除了。
            registrationTask = nil
            throw error
        }
    }

    private func performRegistration() async throws -> Registration {
        guard service.isSupported else {
            throw AttestationError.notSupported
        }

        let challenge = try await challengeProvider.nextChallenge()
        let keyId = try await service.generateKey()

        // attestKey 要的 clientDataHash 是 SHA256(challenge 的原始位元組)。
        let clientDataHash = Data(SHA256.hash(data: challenge.value))
        let attestation = try await service.attestKey(keyId, clientDataHash: clientDataHash)

        var request = URLRequest(url: baseURL.appendingPathComponent("attestation/register"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(RegisterBody(
            platform: platform,
            challengeId: challenge.id,
            // keyId 本身已經是 base64 字串，直接送；attestation 是原始
            // 位元組，要編成標準 base64（不是 base64url）。
            keyId: keyId,
            attestation: attestation.base64EncodedString()
        ))

        let (data, response) = try await transport.send(request)

        guard response.statusCode == 200 else {
            // 後端不會說明被拒的原因 —— 那是刻意的設計，避免變成攻擊者的
            // oracle。要查原因請看 server log。
            throw AttestationError.registrationRejected
        }

        let decoded = try JSONDecoder().decode(RegisterResponse.self, from: data)

        guard decoded.status == "trusted", let deviceId = decoded.deviceId else {
            throw AttestationError.registrationRejected
        }

        let registration = Registration(keyId: keyId, deviceId: deviceId)
        try store.save(registration)

        return registration
    }

    // MARK: - 單次請求

    private func attempt(
        _ request: URLRequest,
        using registration: Registration
    ) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url else {
            throw AttestationError.invalidRequest("URLRequest 沒有 URL")
        }

        let challenge = try await challengeProvider.nextChallenge()

        let requestHash = RequestHash.compute(
            method: request.httpMethod ?? "GET",
            // 用 percent-encoded 且不含 query 的 path。
            // 理由見 RequestHash.path(of:) 的註解 —— 用 URL.path 會因為
            // 自動解碼而跟後端算出不同的值。
            path: RequestHash.path(of: url),
            body: request.httpBody ?? Data(),
            challenge: challenge.value
        )

        // assertion 簽的是 SHA256(requestHash 這串 ASCII 字元)。
        let clientDataHash = Data(SHA256.hash(data: Data(requestHash.utf8)))
        let assertion = try await service.generateAssertion(
            registration.keyId,
            clientDataHash: clientDataHash
        )

        var signed = request
        signed.setValue(platform, forHTTPHeaderField: AttestationHeaders.platform)
        signed.setValue(registration.deviceId, forHTTPHeaderField: AttestationHeaders.deviceId)
        signed.setValue(challenge.id, forHTTPHeaderField: AttestationHeaders.challengeId)
        signed.setValue(requestHash, forHTTPHeaderField: AttestationHeaders.requestHash)
        signed.setValue(assertion.base64EncodedString(), forHTTPHeaderField: AttestationHeaders.assertion)

        return try await transport.send(signed)
    }

    // MARK: - 傳輸用的型別

    private struct RegisterBody: Encodable {
        let platform: String
        let challengeId: String
        let keyId: String
        let attestation: String
    }

    private struct RegisterResponse: Decodable {
        let deviceId: String?
        let status: String
    }
}
