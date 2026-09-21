import Foundation
import Security

/// 註冊成功後要記住的東西。
public struct Registration: Equatable, Sendable, Codable {
    /// `generateKey()` 給的 keyId（base64 字串）。
    public let keyId: String

    /// 後端發的裝置識別。
    public let deviceId: String

    public init(keyId: String, deviceId: String) {
        self.keyId = keyId
        self.deviceId = deviceId
    }
}

/// 存放 keyId 與 deviceId。
///
/// 注意這裡存的**不是機密資料** —— 私鑰在 Secure Enclave 裡，誰都拿不出來，
/// keyId 只是一個識別字串。用 Keychain 的真正理由是它能跨 App 重裝前的
/// 備份還原行為做控制，而且不會像 UserDefaults 那樣被隨手清掉。
public protocol AttestationStore: Sendable {
    func load() throws -> Registration?
    func save(_ registration: Registration) throws
    func clear() throws
}

/// Keychain 實作。
public struct KeychainAttestationStore: AttestationStore {

    private let service: String
    private let account: String

    /// - Parameters:
    ///   - service: Keychain 的 service 名稱，建議用你們的 bundle id
    ///   - account: 同一個 service 下的識別字串
    public init(service: String, account: String = "app-attest-registration") {
        self.service = service
        self.account = account
    }

    public func load() throws -> Registration? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess, let data = item as? Data else {
            throw KeychainError(status: status, operation: "load")
        }

        return try JSONDecoder().decode(Registration.self, from: data)
    }

    public func save(_ registration: Registration) throws {
        let data = try JSONEncoder().encode(registration)

        // 先刪再加。SecItemUpdate 在「原本沒有」時會失敗，而這裡兩種情況
        // （第一次註冊 / 重新註冊）都要能處理。
        SecItemDelete(baseQuery() as CFDictionary)

        var query = baseQuery()
        query[kSecValueData as String] = data

        // kSecAttrAccessibleAfterFirstUnlock：裝置開機解鎖過一次之後就可讀。
        //
        // 不要用預設的 WhenUnlocked —— 那樣 App 在背景執行（推播喚醒、
        // background fetch）而裝置正鎖著時，會讀不到註冊資料，於是重新
        // 註冊，產生一堆多餘的金鑰。
        //
        // 也不要用 ThisDeviceOnly 以外的選項去同步到 iCloud：keyId 綁定的是
        // 這台裝置的 Secure Enclave，同步到別台裝置上完全沒有意義。
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

        let status = SecItemAdd(query as CFDictionary, nil)

        guard status == errSecSuccess else {
            throw KeychainError(status: status, operation: "save")
        }
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status, operation: "clear")
        }
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

public struct KeychainError: Error, LocalizedError {
    public let status: OSStatus
    public let operation: String

    public var errorDescription: String? {
        let message = SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
        return "Keychain \(operation) 失敗（OSStatus \(status)）：\(message)"
    }
}

/// 測試與模擬器用的記憶體實作。
public final class InMemoryAttestationStore: AttestationStore, @unchecked Sendable {

    private let lock = NSLock()
    private var registration: Registration?

    public init(registration: Registration? = nil) {
        self.registration = registration
    }

    public func load() throws -> Registration? {
        lock.lock()
        defer { lock.unlock() }
        return registration
    }

    public func save(_ registration: Registration) throws {
        lock.lock()
        defer { lock.unlock() }
        self.registration = registration
    }

    public func clear() throws {
        lock.lock()
        defer { lock.unlock() }
        registration = nil
    }
}
