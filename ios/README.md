# AppAttestClient — iOS 端

搭配 `../` 那份 PHP 後端的客戶端。Swift 5.9 / iOS 15+ / 零第三方相依。

```bash
swift test    # 28 個測試
```

---

## 用法

```swift
import AppAttestClient

let client = AttestedClient(
    baseURL: URL(string: "https://api.example.com")!,
    service: DeviceCheckAttestationService(),
    store: KeychainAttestationStore(service: Bundle.main.bundleIdentifier!)
)

var request = URLRequest(url: URL(string: "https://api.example.com/protected/echo")!)
request.httpMethod = "POST"
request.httpBody = Data(#"{"message":"hi"}"#.utf8)

let (data, response) = try await client.send(request)
```

`send(_:)` 負責全部的事：確認已註冊（沒有就註冊）→ 取 challenge → 算 requestHash → 簽 assertion → 裝 header → 送出 → 收到 401 就重新註冊並重試一次。

登出時呼叫 `try await client.reset()` 清掉註冊。

---

## ⚠️ 整合時最容易卡住的一件事：環境不匹配

App Attest 的 attestation 裡有一個 `aaguid` 欄位標示它來自哪個環境，**後端會檢查它**。對不上就一律拒絕，而且後端（刻意）不會告訴你原因。

| App 怎麼跑的 | attestation 的環境 | 後端的 `ATTEST_ENVIRONMENT` 要設 |
|---|---|---|
| Xcode 直接跑到真機 | `development` | `development` |
| TestFlight | `production` | `production` |
| App Store | `production` | `production` |
| 模擬器 | **完全不支援** | — |

**TestFlight 算 production**，這點最常被誤會 —— 開發階段一切正常，一上 TestFlight 就全部 401。

要讓 Xcode 直接跑的 build 也用 production 環境，在 entitlements 加：

```xml
<key>com.apple.developer.devicecheck.appattest-environment</key>
<string>production</string>
```

---

## 模擬器怎麼開發

`DCAppAttestService.isSupported` 在模擬器一律是 `false`，所以真的實作跑不起來。用 `StubAttestationService`：

```swift
#if targetEnvironment(simulator)
let service: AttestationService = StubAttestationService()
#else
let service: AttestationService = DeviceCheckAttestationService()
#endif
```

`StubAttestationService` 整個型別包在 `#if DEBUG` 裡，**release build 裡它根本不存在**。這不是潔癖：如果它能被編進 release，某天某個人為了讓模擬器跑得動而留下一行 fallback，整套 attestation 就等於關掉了，而且 App 表面上一切正常。讓它在編譯層面就不存在，這種事就不可能發生。

它產生的是假的 attestation，**後端一定會拒絕**。用途是讓你在模擬器上能跑到「送出請求」為止，不是讓驗證通過。

---

## requestHash：唯一要跟後端逐位元組對齊的東西

```
requestHash = base64url_nopad(
    SHA256( METHOD ‖ "\n" ‖ path ‖ "\n" ‖ SHA256(body) ‖ "\n" ‖ challenge )
)
```

實作在 `Sources/AppAttestClient/RequestHash.swift`。

### 跨語言測試

`Tests/AppAttestClientTests/Fixtures/request-hash-vectors.json` 有 80 組向量，**由後端的 PHP 實作產生**，兩邊各有一個測試驗證同一份檔案：

- 改了 Swift → `CrossLanguageVectorTests` 紅
- 改了 PHP → 後端的 `CrossLanguageVectorTest` 紅
- 要改合約 → 跑 `php tools/generate-request-hash-vectors.php` 重新產生，兩邊同時發版

向量涵蓋空 body、4KB body、含 null byte 的 body、中文與 emoji、percent-encoded 的 path、被編碼的斜線 —— 也就是兩種語言最容易產生歧異的地方。

### 一個已經處理掉的陷阱

`URL.path` 會把 percent-encoding **解碼**：

```swift
URL(string: "https://x.com/a%20b")!.path    // "/a b"    ← 解碼過
components.percentEncodedPath                // "/a%20b"  ← 線上實際傳的
```

後端看到的是 `REQUEST_URI`，也就是線上實際傳的那份。所以必須用 `percentEncodedPath`（`RequestHash.path(of:)` 已經處理）。用錯的話，只有含非 ASCII 或 `%XX` 的 path 會驗不過，其他一切正常 —— 是最難查的那種 bug。

---

## 延遲：每個受保護請求是 2 個 round trip

目前合約要求每個請求都先拿一個新 challenge。安全性最好，但使用者體感上每個動作都慢一倍。

如果量測下來不能接受，替代方案是實作一個會預先抓一批 challenge 的 `ChallengeProvider`：延遲回到正常，代價是 challenge 在裝置上存活較久、TTL 要拉長、replay 的時間窗變大。

換方案只需要換 `ChallengeProvider` 的實作，`AttestedClient` 一行都不用改。

---

## 設計上的三個決定

**`AttestedClient` 是 actor。** App 啟動時常常同時發好幾個請求。不序列化的話每一個都會發現「還沒註冊」然後各自跑一次註冊，產生好幾把金鑰、好幾個 deviceId，只有最後寫進 Keychain 的那個有用。測試 `testConcurrentRequestsRegisterOnlyOnce` 守這件事。

**401 會自動重新註冊並重試一次。** 後端可能撤銷裝置，iOS 也可能讓金鑰失效（系統還原、`DCError.invalidKey`）。沒有這段的話使用者會卡在永久 401，唯一解法是重裝 App，而他們不會知道。只重試一次，避免無限迴圈打爆後端。

**Keychain 用 `AfterFirstUnlockThisDeviceOnly`。** 不用預設的 `WhenUnlocked`，否則 App 在背景執行（推播喚醒、background fetch）而裝置鎖著時會讀不到註冊資料，於是重新註冊，累積一堆多餘的金鑰。也不同步到 iCloud —— keyId 綁的是這台裝置的 Secure Enclave，同步到別台機器毫無意義。

---

## 測試涵蓋範圍

**驗得到（28 個測試，不需要真機）**

- requestHash 與後端逐位元組一致（80 組跨語言向量）
- percent-encoding、query string 的處理
- 註冊時機：第一次請求才註冊、已註冊不重複註冊
- 併發：10 個同時的請求只註冊一次
- 401 → 重新註冊 → 重試一次；重試後仍 401 就放棄
- 非 401 的錯誤不觸發重新註冊
- 註冊失敗後下一次呼叫能重新嘗試（失敗的 task 不會卡住後續）
- header 齊全、原始 request 的 method/body 不被改動
- assertion 簽的是 `SHA256(requestHash 字串)`

**驗不到（需要真機）**

- `DCAppAttestService` 的實際呼叫。這部分由 `AttestationService` protocol 隔開，型別正確、編譯得過，但沒有在真機上執行過。

第一次接到真機上時，建議先確認的順序：`isSupported` 是不是 `true` → `generateKey()` 有沒有拿到 keyId → 後端 register 回什麼。前兩步失敗是裝置/設定問題，第三步失敗才去看 server log。
