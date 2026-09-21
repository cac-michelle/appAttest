import Foundation

/// 實際送出 HTTP 請求的東西。
///
/// 抽出來是為了測試能換掉 —— `AttestedClient` 的註冊流程、401 重試、
/// 併發控制都可以在不碰網路的情況下測完整。
public protocol Transport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// 用 `URLSession` 的預設實作。
public struct URLSessionTransport: Transport {

    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw AttestationError.invalidServerResponse("回應不是 HTTPURLResponse")
        }

        return (data, http)
    }
}
