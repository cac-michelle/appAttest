# App Attest 後端驗證 — 參考實作設計文件

日期：2026-09-21
狀態：已核可，待實作
交付對象：後端工程團隊（PHP 8.1）

## 1. 這份東西是什麼

一份**可執行的規格**。後端要在自己的服務裡實作 Apple App Attest 驗證，這個 repo 提供：

1. 零框架相依的 PHP 驗證核心 —— 可直接複製進他們的專案。
2. 逐步印出驗證過程的 demo 腳本 —— 讓人看懂每個步驟在算什麼。
3. 本文件 —— byte 級的規格描述，語言中立，就算最後改用別的語言也依然準確。

### 目標

- 完整執行 Apple 規範的七項註冊檢查，不省略任何一步。
- 每次受保護請求驗 assertion 簽章、requestHash 綁定、counter 嚴格遞增。
- 附自簽憑證測試夾具，讓整條流程在沒有 iPhone 的情況下可端到端測試。
- 程式碼以「可讀懂、可移植」為第一優先，效能次之。

### 非目標

- 不實作 Android / Play Integrity 驗證器（介面保留，見 §8）。
- 不解析 Apple attestation 的 `receipt`（fraud metric / 風險評估）。
- 不做憑證撤銷檢查（CRL / OCSP）。
- 不綁任何 PHP 框架。
- 不實作 iOS client；測試夾具扮演 client 角色。

## 2. 技術選型

| 項目 | 選擇 | 說明 |
|---|---|---|
| 語言 | PHP 8.1+ | 用 `enum`、`readonly` 屬性表達驗證結果 |
| 密碼學 | `ext-openssl`（內建） | X.509、ECDSA P-256、SHA-256 |
| CBOR | 自寫的嚴格子集解碼器 | 見下方說明 |
| 儲存 | SQLite via `ext-pdo_sqlite` | 藏在 interface 後，見 §7 |
| HTTP | PHP 內建 server + 極簡 router | **僅供 demo**，不是要他們照抄的部分 |
| 測試 | PHPUnit 10 | 測試本身即攻擊場景文件 |

**runtime 零 composer 相依**（PHPUnit 只是 dev 相依）。

### CBOR：為什麼自己寫而不用 `spokky-labs/cbor-php`

原本規劃用現成套件，實作時改為自寫約 180 行的嚴格解碼器，理由有二：

1. 這是要被複製進別人專案的參考實作。零相依表示接手的團隊不必為了驗 attestation 去爭取一個新套件。
2. App Attest 只用到 CBOR 的一小塊（definite-length 的 map / array / byte string / text string / 整數）。**只接受這個子集、其餘一律拒絕**，比接上泛用解碼器更安全 —— 這裡解的是攻擊者能完全控制的位元組。

明確拒絕：indefinite-length、tag、float / simple value、結尾多餘位元組、重複的 map key、超過 16 層的巢狀。這些都不該出現在合法的 attestation 裡。

要換回套件的話只需改 `CborDecoder::decode()` 一個進入點，其餘程式碼不受影響。`src/Cbor/CborEncoder.php` 只有測試夾具在用，後端不需要。

驗證核心（`src/Verification/`）不 import 任何 HTTP 或儲存相關的東西。輸入是 bytes 與設定值，輸出是 `VerifyResult`。這是他們真正要搬走的部分。

## 3. API 合約

### 3.1 `POST /attestation/challenge`

```
Request:  { "platform": "ios" }
Response: { "challenge": "<base64url, 32 bytes 隨機>",
            "challengeId": "<uuid4>",
            "expiresAt": "<RFC 3339 UTC>" }
```

- challenge：`random_bytes(32)`，base64url 無 padding 編碼。
- TTL：預設 300 秒，可設定。
- `platform` 只接受 `"ios"`；其他值回 400。此欄位僅用於路由，不構成任何信任基礎 —— 真正的平台證明來自 attestation 裡的 App ID。

### 3.2 `POST /attestation/register`

```
Request:  { "platform": "ios",
            "challengeId": "...",
            "keyId": "<base64, generateKey 的輸出>",
            "attestation": "<base64, attestKey 的輸出>" }
Response: { "deviceId": "<uuid4>", "status": "trusted" | "rejected" }
```

驗證失敗回 HTTP 401，body 為 `{"deviceId": null, "status": "rejected"}`。失敗原因只寫 log，不回給 client。

### 3.3 受保護請求（demo 端點 `POST /protected/echo`）

```
Headers:
  X-Attest-Platform:     "ios"
  X-Attest-Device-Id:    "<register 取得>"
  X-Attest-Challenge-Id: "<這次先拿的 challenge>"
  X-Attest-Request-Hash: "<見 §4>"
  X-Attest-Assertion:    "<base64, generateAssertion 輸出>"
```

驗證通過才執行業務邏輯。業務邏輯只讀 `$result->trusted`，不碰平台細節。

## 4. requestHash 定義

合約要求「請求內容 + challenge 算出的 hash」，但未定死算法。client 與 server 必須逐位元組一致，因此定義為：

```
requestHash = base64url_nopad(
    SHA256( method ‖ "\n" ‖ path ‖ "\n" ‖ SHA256(body) ‖ "\n" ‖ challenge_bytes )
)
```

- `method`：大寫 ASCII，如 `POST`。
- `path`：不含 query string 的 URL path。
- `SHA256(body)`：原始 request body 位元組的**二進位**摘要（不是 hex 字串）。空 body 為空字串的摘要。
- `challenge_bytes`：challengeId 對應的 challenge **原始 32 bytes**，不是 base64 字串。

PHP：`hash('sha256', $data, true)` —— 第三個參數 `true` 代表回傳 raw binary。忘了加就會算出完全不同的值，這是最常見的踩雷點。

challenge 混入 hash，requestHash 因此天生綁定這次的 challengeId。

**server 永遠自己重算。** 收到請求後用實際的 method / path / body 與查出的 challenge 重算 requestHash，再與 header 值用 `hash_equals()` 比對。header 送來的值從不被信任，只用於比對。

assertion 的 clientData 即 requestHash 的 ASCII 字串：

```
clientDataHash = SHA256(requestHash_string)
```

## 5. 註冊時的 attestation 驗證

### 5.1 結構

attestation 是 CBOR map：

```
{ "fmt": "apple-appattest",
  "attStmt": { "x5c": [credCert_der, intermediateCert_der], "receipt": bytes },
  "authData": bytes }
```

`authData` 位元組佈局（用 `substr()` 逐段切，總長至少 87 + COSE 長度）：

| offset | 長度 | 欄位 |
|---|---|---|
| 0 | 32 | `rpIdHash` |
| 32 | 1 | `flags` |
| 33 | 4 | `signCount`（big-endian，`unpack('N', ...)`） |
| 37 | 16 | `aaguid` |
| 53 | 2 | `credentialIdLength`（big-endian，`unpack('n', ...)`，須為 32） |
| 55 | 32 | `credentialId` |
| 87 | … | `credentialPublicKey`（COSE_Key CBOR） |

COSE_Key（EC2 / P-256）預期欄位：`1`(kty)=`2`、`3`(alg)=`-7`、`-1`(crv)=`1`、`-2`(x)=32 bytes、`-3`(y)=32 bytes。

### 5.2 COSE_Key → OpenSSL 可用的公鑰（PHP 特有的坑）

PHP 沒有「從 x, y 座標建 EC 公鑰」的 API。做法是手工組出 DER 格式的 SubjectPublicKeyInfo 再包成 PEM：

```
固定前綴（hex）：3059301306072a8648ce3d020106082a8648ce3d030107034200
接上：04 ‖ X(32 bytes) ‖ Y(32 bytes)
整段 base64 後包 -----BEGIN PUBLIC KEY----- / -----END PUBLIC KEY-----
丟進 openssl_pkey_get_public()
```

前綴是「ecPublicKey + prime256v1 + BIT STRING(66 bytes)」的固定 DER 編碼，對 P-256 而言永遠不變。這段獨立成 `CoseKey::toPem()`，附註解說明每個 byte。

### 5.3 七項檢查

1. **fmt** 必須是 `apple-appattest`。
2. **憑證鏈**：`credCert` 由 `intermediateCert` 簽發、`intermediateCert` 由設定的 root CA 簽發；三者皆在有效期內。用 `openssl_x509_verify($cert, $issuerPubKey)`（回傳 1 才算過）逐層驗，有效期用 `openssl_x509_parse()` 的 `validFrom_time_t` / `validTo_time_t` 檢查。不做撤銷檢查。
3. **nonce**：`clientDataHash = SHA256(challenge_bytes)`；`nonce = SHA256(authData ‖ clientDataHash)`。解析 `credCert` 的 extension OID `1.2.840.113635.100.8.2`，其內容為 DER `SEQUENCE { [1] { OCTET STRING nonce } }`，取出的 32 bytes 須等於算出的 nonce（用 `hash_equals()` 比對）。
4. **keyId**：從 COSE_Key 取 x、y，組出未壓縮點 `0x04 ‖ x ‖ y`，`SHA256` 後須等於 request 傳來的 `keyId`，也須等於 `authData` 中的 `credentialId`。
5. **App ID**：`rpIdHash == SHA256("<TeamID>.<BundleID>")`，App ID 來自設定。
6. **counter**：`signCount == 0`。
7. **環境**：`aaguid` 等於 `"appattestdevelop"`（development，剛好 16 bytes）或 `"appattest" + "\x00" × 7`（production），依設定值判定。

全數通過才：發 `deviceId`、存 `deviceId → (公鑰 PEM, counter = 0, platform)`、作廢 challengeId。

### 5.4 nonce extension 的取法

`openssl_x509_parse()` 對於 OpenSSL 不認得的 OID，會把原始 extnValue 放進 `['extensions']['1.2.840.113635.100.8.2']`。取出後需自行剝 DER：

```
30 LL            SEQUENCE
   A1 LL         [1] context-specific, constructed
      04 20      OCTET STRING, 32 bytes
         <32 bytes nonce>
```

實作寫一個最小 DER reader（讀 tag、讀長度、讀 value），**不要**用「取最後 32 bytes」這種捷徑 —— 能動但脆弱，且看不出結構。

**已實測確認**（PHP 8.5.10 / OpenSSL 3.6.1）：`openssl_x509_parse()` 對這個未知 OID 回傳完整的 38 bytes 原始 DER，二進位安全、未被截斷。原本規劃的「直接解析憑證原始 DER」備案不需要。若你們的 PHP / OpenSSL 版本組合行為不同，該備案仍是可行方向。

## 6. 每次請求的 assertion 驗證

assertion 是 CBOR map：`{ "signature": bytes, "authenticatorData": bytes }`。

`authenticatorData` 為 `rpIdHash(32) ‖ flags(1) ‖ signCount(4)`，**無** attested credential data —— 跟註冊時的 `authData` 佈局不同，只有 37 bytes。

步驟：

1. 用 challengeId 取出 challenge：必須存在、未過期、未使用（原子消耗，見 §7）。
2. 依 §4 重算 requestHash，與 header 用 `hash_equals()` 比對。
3. `clientDataHash = SHA256(requestHash 字串)`；`nonce = SHA256(authenticatorData ‖ clientDataHash)`。
4. 以 deviceId 查出的公鑰驗簽章：`openssl_verify($nonce, $signature, $pubKey, OPENSSL_ALGO_SHA256)`，須回傳 `1`。
   - 訊息是 `nonce` 這 32 bytes 本身，OpenSSL 會再對它做一次 SHA-256。這是 Apple 規範的定義，不是 bug。
   - `$signature` 是 DER 編碼的 ECDSA 簽章，正好是 `openssl_verify()` 期待的格式，不需轉換。
   - 回傳值要嚴格比對 `=== 1`；`0` 是驗證失敗、`-1` 是錯誤，用 `if (!openssl_verify(...))` 會把 `-1` 當成通過。
5. `rpIdHash == SHA256(appId)`。
6. `signCount > 已存 counter`（**嚴格**遞增，相等也要拒絕）。
7. 作廢 challengeId，更新 counter。

challengeId 的一次性消耗是防 replay 的第一道防線，counter 嚴格遞增是第二道。

## 7. 資料模型與儲存介面

```php
enum Reason: string { /* §9 的代碼 */ }

final class VerifyResult {
    public function __construct(
        public readonly bool $trusted,
        public readonly string $platform,
        public readonly ?string $deviceId,
        public readonly array $reasons,   // Reason[]
    ) {}
}
```

```php
interface ChallengeStore {
    public function issue(string $platform): Challenge;
    public function consume(string $challengeId): ?Challenge;  // 原子操作
    public function purgeExpired(): int;
}

interface DeviceStore {
    public function create(string $publicKeyPem, string $platform): string;
    public function get(string $deviceId): ?Device;
    public function updateCounter(string $deviceId, int $counter): void;
}
```

### 為什麼是 SQLite 而不是記憶體

PHP 是 shared-nothing：每個 request 都是全新的 process，記憶體狀態不跨 request 存在。challenge 與 device 必須進外部儲存。

**`consume()` 必須是單一原子操作**，不能是「先查、再標記」兩步 —— 兩個併發請求會同時查到同一個未使用的 challenge，replay 防護直接破功。SQLite 實作：

```sql
UPDATE challenges SET used_at = :now
 WHERE id = :id AND used_at IS NULL AND expires_at > :now
```

檢查 affected rows：為 `1` 才算成功消耗，然後才 SELECT 出 challenge 內容；為 `0` 代表不存在 / 已用 / 已過期，三者對外一律視為失敗。

這段是整個實作裡最容易寫錯、後果最嚴重的地方，demo 會明確示範，測試會涵蓋併發情境。換成 Redis 時對應的是 `GETDEL` 或 Lua script；換成 MySQL 時是同樣的 `UPDATE ... WHERE` 搭配 affected rows。呼叫端不需更動。

## 8. 驗證抽象層

```php
interface AttestationVerifier {
    public function verifyRegistration(RegisterRequest $req): VerifyResult;
    public function verifyRequest(RequestContext $ctx): VerifyResult;
}
```

`VerifierRegistry` 依 `platform` 路由。本次只註冊 iOS 驗證器；`platform` 為其他值時回 400，不落入任何驗證器。

保留介面的理由：日後加入 Android 驗證器時，API 層、header 結構、業務邏輯皆不需更動。成本約 20 行。

## 9. 錯誤處理

所有失敗回傳 `VerifyResult(trusted: false, reasons: [...])`，reason 為 `enum Reason` 的 case：

`CHALLENGE_NOT_FOUND`、`CHALLENGE_EXPIRED`、`CHALLENGE_ALREADY_USED`、`BAD_CBOR`、`BAD_FMT`、`CERT_CHAIN_INVALID`、`CERT_EXPIRED`、`NONCE_MISMATCH`、`KEY_ID_MISMATCH`、`APP_ID_MISMATCH`、`COUNTER_NOT_ZERO`、`AAGUID_MISMATCH`、`DEVICE_NOT_FOUND`、`REQUEST_HASH_MISMATCH`、`SIGNATURE_INVALID`、`COUNTER_NOT_INCREASING`、`BAD_COSE_KEY`、`MALFORMED_AUTH_DATA`。

**對外一律只回 `rejected` / HTTP 401**，reasons 只寫入 log。避免攻擊者靠錯誤訊息逐步探測自己卡在哪一關。

驗證核心不丟例外表示「驗證失敗」—— 失敗是預期中的正常結果，用回傳值表達。例外只用於程式錯誤（如設定檔缺失）。

## 10. 設定

| 環境變數 | 說明 | 預設 |
|---|---|---|
| `APP_ID` | `<TeamID>.<BundleID>` | 無，必填 |
| `ATTEST_ENVIRONMENT` | `development` / `production`，決定預期 aaguid | `development` |
| `APPLE_ROOT_CA_PEM` | root CA 憑證檔路徑 | `certs/apple-app-attest-root-ca.pem` |
| `CHALLENGE_TTL_SECONDS` | challenge 有效秒數 | `300` |
| `SQLITE_PATH` | SQLite 檔案路徑 | `var/attest.sqlite` |

測試時 `APPLE_ROOT_CA_PEM` 指向夾具產生的自簽 root CA；正式環境指向 Apple 官方 root（自 <https://www.apple.com/certificateauthority/private/> 下載 “Apple App Attest Root CA”）。同一份程式碼、同一組驗證邏輯，只換信任錨點。

## 11. 測試策略

先寫測試再寫實作。測試本身就是給後端看的攻擊場景文件，命名要能直接讀懂在防什麼。

### 11.1 假裝置夾具 `tests/Fixture/FakeDevice.php`

用 `openssl_csr_*` / `openssl_x509_*` 產生自簽 root CA → intermediate → credCert（含真的 nonce extension，透過 openssl.cnf 的自訂 OID 寫入），模擬一台 iPhone：

- `attest(string $challenge): array` —— 回傳 `[keyId, attestationBytes]`，完整合法。
- `assertRequest(string $requestHash): string` —— 合法 assertion，內部 counter 自動遞增。
- 可控的錯誤注入：nonce 錯、counter 不為 0、counter 不遞增、App ID 不符、aaguid 不符、憑證鏈斷、keyId 不符、簽章被竄改。

夾具產生的憑證在測試啟動時建一次並快取，避免每個 test case 都花時間產金鑰。

### 11.2 測試層級

- **單元**：§5.3 每一項檢查各一個失敗案例 + 一個成功案例，直接呼叫驗證函式。
- **requestHash**：黃金測試向量（固定輸入 → 固定輸出的 base64url 字串）。確保未來任何改動不會默默破壞 client 相容性 —— 這個測試壞掉就代表 iOS 端也得同步改。
- **COSE → PEM**：已知 x/y 產生已知 PEM 的向量測試。
- **store**：TTL 過期、重複 `consume()` 第二次回 `null`、counter 更新。
- **API 整合**：challenge → register → 受保護請求的完整流程；以及三種攻擊皆被拒：同一 challengeId 用兩次（replay）、body 被竄改（requestHash 對不上）、counter 回放。
- **真實 HTTP**（實作時新增，原規劃沒有）：啟動 `php -S`，透過跨 process 的真實請求跑完整流程。

### 11.3 為什麼需要真實 HTTP 層的測試

實作過程踩到一個只有這層才抓得到的 bug：`Logger` 原本用 `fwrite(STDERR, …)`，而 `STDERR` 只有 CLI SAPI 會定義。logger 只在**驗證失敗時**被呼叫，所以症狀是「拒絕路徑整個壞掉」—— 本該回 401 的請求變成帶 HTML 錯誤頁的 200。所有 CLI 測試全綠。

這類 bug 有一整個家族：SAPI 差異、`HTTP_X_ATTEST_*` 的 header 名稱轉換、`php://input` 讀 body、從 `REQUEST_URI` 去掉 query string。直接建構 `Request` 物件的測試會把它們全部繞過。

### 11.4 變異測試

實作完成後跑過一輪人工變異驗證，確認測試不是裝飾。六項全被抓到：counter 檢查改成 `<`、跳過 nonce 比對、`hash()` 漏掉 raw binary 的 `true`、跳過憑證鏈簽章驗證、不比對 App ID、challenge 消耗改成非原子。

建議後端移植後也做一次同樣的事 —— 「測試通過」和「測試有在測東西」是兩件事。

## 12. Demo 腳本

`demo/walkthrough.php` —— 用假裝置跑完整條流程，每一步印出實際的 bytes、算出的 nonce、比對結果：

```
[1] 取得 challenge
    challenge (base64url) = ...
[2] 假裝置產生 attestation
    authData 長度 = 517 bytes
      rpIdHash   = <hex>
      signCount  = 0
      aaguid     = "appattestdevelop"
    ...
[3] 後端驗證
    ✓ fmt = apple-appattest
    ✓ 憑證鏈：credCert ← intermediate ← root CA
    ✓ nonce：SHA256(authData ‖ SHA256(challenge)) = <hex>
      credCert extension 1.2.840.113635.100.8.2 = <hex>  一致
    ...
[4] 攻擊場景
    重放同一個 challengeId  → rejected (CHALLENGE_ALREADY_USED)
    竄改 request body       → rejected (REQUEST_HASH_MISMATCH)
    counter 回放            → rejected (COUNTER_NOT_INCREASING)
```

這是給人看的，目的是讓後端在讀程式碼之前先對整個流程有具體的感覺。

## 13. 檔案結構

```
src/
  App.php                             相依組裝（一個地方看完整張圖）
  Config.php                          設定物件
  RequestHash.php                     §4 的算法
  Base64Url.php
  Cbor/
    CborDecoder.php                   嚴格子集解碼器
    CborEncoder.php                   只有測試夾具用；後端不需要
    CborException.php
  Verification/
    VerifyResult.php  Reason.php      §7 / §9
    VerificationFailure.php           內部例外 → 邊界轉回傳值
    AttestationVerifier.php           interface
    VerifierRegistry.php              platform 路由
    RegisterRequest.php  RequestContext.php
    Ios/
      IosVerifier.php                 實作 interface，串流程
      AttestationValidator.php        §5.3 七項檢查
      AssertionValidator.php          §6
      ValidatedAttestation.php
      AuthData.php                    authData / authenticatorData 解析
      CoseKey.php                     §5.2 COSE → PEM
      CertChain.php                   憑證鏈驗證
      NonceExtension.php              §5.4 nonce 取出
      Der.php                         最小 DER reader
  Store/
    ChallengeStore.php  DeviceStore.php   interface
    Challenge.php  Device.php
    Sqlite/                               實作 + schema + Uuid
  Http/                               demo router 與 handler（不是核心）
tests/
  Fixture/FakeAppleCa.php  FakeDevice.php  Flaw.php
  Support/TestEnv.php
  Unit/         RequestHash / Cbor / CoseKey / Attestation / Assertion / ChallengeStore
  Integration/  FullFlowTest.php  HttpServerTest.php
demo/
  walkthrough.php
public/
  index.php                           demo 入口
certs/
  README.md                           如何取得 Apple root CA
README.md                             給後端的入口文件
```

## 14. 已知限制

1. 不做 CRL / OCSP 撤銷檢查。正式環境應評估補上。
2. 不解析 `receipt`，因此無法取得 Apple 的 fraud metric，也無法做 attestation 的有效期延展。
3. SQLite 適合 demo 與單機；正式環境請換 Redis（challenge，天然 TTL）或既有的資料庫（device）。`consume()` 的原子語意必須一併確保，見 §7。
4. demo 的 HTTP 層是最小實作，沒有 rate limiting、沒有認證、沒有 CORS 設定，**不可直接上線**。
5. client 端的 TLS cert pinning 屬 iOS 責任，不在本 repo 範圍。
