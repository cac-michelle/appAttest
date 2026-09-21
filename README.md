# Apple App Attest — 後端驗證參考實作

給後端工程師的**可執行規格**。目的不是當成套件安裝，而是讓你們看懂 App Attest 該怎麼驗，然後把核心搬進自己的專案。

PHP 8.1+ · runtime 零相依（只用 `ext-openssl` 和 `ext-pdo_sqlite`）

---

## 先跑這個

```bash
composer install
php demo/walkthrough.php
```

會逐步印出一次完整流程：challenge → 產生 attestation → 七項檢查（含實際算出的 nonce 與憑證裡的值）→ 受保護請求 → 七種攻擊被擋下。用的是假的 Apple CA 和假裝置，但**驗證程式碼跟正式環境完全相同**。

接著跑測試：

```bash
vendor/bin/phpunit
```

85 個測試。每個否定案例對應一種真實攻擊，測試名稱就是在防什麼。

---

## 閱讀順序

`src/` 有 39 個檔案，但**主線只有 4 個**。照這個順序看，一小時內可以掌握全貌。

### 第一輪：搞懂在做什麼（約 30 分鐘）

| # | 檔案 | 為什麼先看這個 |
|---|---|---|
| 0 | `php demo/walkthrough.php` | 先看到全貌再看程式碼。每一步的實際 bytes 都印出來了 |
| 1 | `src/RequestHash.php` | 最小、最獨立，而且是**唯一要跟 iOS 端逐位元組對齊**的東西 |
| 2 | `src/Verification/Ios/AttestationValidator.php` | 註冊的七項檢查，一個檔案從頭讀到尾就是完整的註冊驗證 |
| 3 | `src/Verification/Ios/AssertionValidator.php` | 每次請求做什麼。比註冊簡單很多 |
| 4 | `src/Store/Sqlite/SqliteChallengeStore.php` | 只看 `consume()`。這是最容易寫錯、後果最嚴重的一段 |

看完這四個就知道整套在防什麼了。**其餘檔案都是這四個的零件**，需要時再往下鑽即可。

### 第二輪：需要時再看的零件

從 `AttestationValidator` 往下追會遇到這些，每個都只做一件事：

- `AuthData.php` — 位元組佈局的解析（註冊和每次請求的佈局**不同**，是常見 bug 來源）
- `CoseKey.php` — COSE 公鑰 → PEM，PHP 最卡的一段
- `NonceExtension.php` + `Der.php` — 從憑證挖出 Apple 埋的 nonce
- `CertChain.php` — 憑證鏈驗證
- `IosVerifier.php` — 把上面這些跟資料庫串起來的流程

### 第三輪：把測試當規格看

`tests/Unit/AttestationValidatorTest.php` 的每個測試方法都對應一種攻擊，註解寫的是「不做這項檢查會被怎麼打」。想確認某個檢查到底在擋什麼，看測試比看實作快。

### 如果只有 15 分鐘

跑 `php demo/walkthrough.php`，然後讀 README 的〈PHP 特有的五個坑〉和〈註冊時的七項檢查〉兩節。這樣至少不會踩到那幾個靜默失效的地雷。

---

## 移植檢查清單

重寫成你們自己的架構時，以下每一項都要逐條核對。**這些不是風格建議，錯了就是安全漏洞**，而且多數不會有任何錯誤訊息。

- [ ] 七項註冊檢查一項都沒少（對照下方表格）
- [ ] 每個 `hash('sha256', …)` 都有第三個參數 `true`
- [ ] `openssl_verify()` / `openssl_x509_verify()` 都是 `=== 1` 判斷，不是 `if (!…)`
- [ ] counter 是**嚴格**遞增（`<=` 拒絕，不是 `<`）
- [ ] requestHash 是 server 自己重算的，header 的值只拿來比對
- [ ] requestHash 的算法跟 `src/RequestHash.php` 逐位元組相同（用黃金測試向量驗）
- [ ] challenge 的消耗是**單一原子操作**，靠 affected rows 判斷成敗
- [ ] 註冊失敗也會消耗掉 challenge（否則攻擊者能用同一個 challenge 無限試）
- [ ] 所有比對敏感值的地方用 `hash_equals()`，不是 `===`
- [ ] challenge 用 `random_bytes()`，不是 `rand()` / `mt_rand()` / `uniqid()`
- [ ] 失敗原因只進 log，對外一律 `401` + `{"status":"rejected"}`
- [ ] 有一組**真實 HTTP** 的測試（見下方第 5 個坑，只跑 CLI 測試會漏掉整類 bug）

移植完建議做一次變異測試：把上面幾項刻意改壞，確認你們的測試抓得到。這個 repo 做過同樣的事，六項全數被抓到 —— 「測試通過」和「測試有在測東西」是兩件事。

---

## 要搬走的是哪些檔案

```
src/Verification/     ← 核心，搬這個
src/Store/            ← 介面搬走，SQLite 實作換成你們的 Redis / MySQL
src/RequestHash.php   ← 搬這個，而且 iOS 端要寫出一模一樣的邏輯
src/Config.php        ← 參考，接上你們的設定系統

src/Http/             ← 不用搬。你們有自己的框架
public/index.php      ← 不用搬
src/Cbor/CborEncoder.php ← 不用搬（只有測試夾具在用，後端只解碼不編碼）
```

`src/Verification/` 不 import 任何 HTTP 或資料庫的東西。輸入是位元組和設定值，輸出是 `VerifyResult`。

---

## 流程

### 註冊（每台裝置一次）

```
App                          後端
 │                            │
 ├── POST /attestation/challenge ──────→│
 │←───── challenge (32 bytes 亂數, 一次性, 5 分鐘) ──┤
 │                            │
 ├─ generateKey() → keyId     │
 ├─ attestKey(keyId, SHA256(challenge)) → attestation
 │                            │
 ├── POST /attestation/register ───────→│
 │    { platform, challengeId, keyId, attestation }
 │                            ├─ 七項檢查（見下）
 │                            ├─ 存 deviceId → (公鑰, counter=0)
 │                            ├─ 作廢 challengeId
 │←───── { deviceId, status: "trusted" } ─────┤
```

### 每次受保護請求

```
 ├── POST /attestation/challenge ──────→│   （每次請求都要一個新的）
 │←───── challenge ────────────────────┤
 │                            │
 ├─ requestHash = f(method, path, body, challenge)
 ├─ generateAssertion(keyId, SHA256(requestHash)) → assertion
 │                            │
 ├── POST /protected/… ────────────────→│
 │    X-Attest-Platform:     ios
 │    X-Attest-Device-Id:    …
 │    X-Attest-Challenge-Id: …
 │    X-Attest-Request-Hash: …
 │    X-Attest-Assertion:    …
 │                            ├─ 消耗 challengeId（一次性）
 │                            ├─ 自己重算 requestHash 並比對
 │                            ├─ 用存的公鑰驗簽章
 │                            ├─ counter 嚴格遞增
 │←───── 200 或 401 ──────────────────┤
```

---

## 註冊時的七項檢查

每一項都對應一種攻擊。少做任何一項就有對應的繞過方式。實作在 `src/Verification/Ios/AttestationValidator.php`。

| # | 檢查 | 不做會怎樣 |
|---|---|---|
| 1 | `fmt == "apple-appattest"` | 可以餵進其他格式的 attestation |
| 2 | 憑證鏈接回 Apple Root CA | 任何人自己開一間 CA 就能簽出「合法」的假金鑰 |
| 3 | nonce == SHA256(authData ‖ SHA256(challenge)) | 攔截到的 attestation 可以無限重放 |
| 4 | keyId == SHA256(公鑰) == credentialId | 存下來的公鑰可能不是 Apple 簽的那一把 |
| 5 | rpIdHash == SHA256(App ID) | 別的 App 的合法 attestation 可以拿來打你的 API |
| 6 | signCount == 0 | 可以拿 assertion 的 authData 冒充 attestation |
| 7 | aaguid 符合環境 | 開發版 App（可被除錯器附加）能存取正式環境 |

---

## PHP 特有的五個坑

這五個地方跟其他語言不一樣，而且錯了的症狀都是「靜默失效」——不會拋例外，只會永遠驗不過或永遠放行。

### 1. `hash()` 的第三個參數

```php
hash('sha256', $data, true)   // ✅ 32 bytes raw binary
hash('sha256', $data)         // ❌ 64 字元 hex 字串
```

漏掉 `true`，算出的所有 hash 都會是錯的。症狀：「簽章明明對卻一直驗不過」。整份程式碼裡每一個 `hash()` 呼叫都要有這個 `true`。

### 2. `openssl_verify()` 回傳 -1

```php
if (openssl_verify(...) !== 1) { reject(); }   // ✅
if (!openssl_verify(...))      { reject(); }   // ❌ -1 會被當成通過
```

`1` = 通過、`0` = 驗證失敗、`-1` = 執行錯誤。`openssl_x509_verify()` 同樣。

### 3. 沒有「從 x,y 座標建 EC 公鑰」的 API

其他語言一行就好，PHP 得手工組 DER 的 SubjectPublicKeyInfo 再包成 PEM。P-256 的前綴是固定的 26 bytes，逐 byte 的說明在 `src/Verification/Ios/CoseKey.php`。

### 4. PHP 是 shared-nothing

每個 request 都是全新的 process，記憶體狀態不跨 request 存在。challenge 一定要進外部儲存，而且消耗動作**必須是單一原子操作**：

```sql
-- ✅ 靠 affected rows 判斷是不是「我」搶到的
UPDATE challenges SET used_at = :now
 WHERE id = :id AND used_at IS NULL AND expires_at > :now
```

寫成「先 SELECT 再 UPDATE」的話，兩個併發請求會同時查到同一個未使用的 challenge，兩個都通過 —— replay 防護直接失效，而且單執行緒測試永遠測不出來。細節在 `src/Store/Sqlite/SqliteChallengeStore.php`。

### 5. 別在 web SAPI 底下寫 `STDERR`

```php
error_log($line);                  // ✅ 所有 SAPI 都能用
fwrite(STDERR, $line);             // ❌ STDERR 只有 CLI SAPI 才定義
```

這個坑特別陰險，因為 **logger 只在驗證失敗時被呼叫**。一旦它在 php-fpm 底下炸掉，本該回 401 的請求會變成 500，或更糟 —— 變成帶 HTML 錯誤訊息的 200。而 CLI 跑的測試全綠，因為 CLI 有 `STDERR`。

開發這個 repo 時真的踩到了。抓到它的是 `tests/Integration/HttpServerTest.php`：那個測試會真的啟動一個 `php -S`，透過 HTTP 打進去。**建議你們也保留一組這樣的測試** —— 有一整類的 bug（SAPI 差異、header 名稱轉換、`php://input`、query string 處理）只有跨 process 的真實請求才看得到。

---

## requestHash

**這是唯一一段 iOS 端必須逐位元組寫成一模一樣的邏輯。**

```
requestHash = base64url_nopad(
    SHA256( METHOD ‖ "\n" ‖ path ‖ "\n" ‖ SHA256(body) ‖ "\n" ‖ challenge )
)
```

- `SHA256(body)` 是 **raw binary**（32 bytes），不是 hex 字串
- `challenge` 是 **原始 32 bytes**，不是 base64 字串
- `path` 不含 query string

把 challenge 混進去，requestHash 就天生綁定這一次的 challenge；把 method 和 path 混進去，攔截者就沒辦法把打到 `/protected/echo` 的簽章轉送到 `/admin/delete-all`。

`tests/Unit/RequestHashTest.php` 有黃金測試向量。**那個測試壞掉 = client 合約變了**，兩邊必須同時改、同時發版。

---

## 失敗原因不回給 client

驗證失敗一律回 `401` + `{"deviceId": null, "status": "rejected"}`。

具體是哪一關沒過（`Reason` enum）只寫進 server log。告訴攻擊者他卡在第幾關，等於免費送他一個 oracle，讓攻擊從盲猜變成有導引的逼近。排查問題請看 server log。

---

## 設定

| 環境變數 | 說明 | 預設 |
|---|---|---|
| `APP_ID` | `<TeamID>.<BundleID>` | 無，**必填** |
| `ATTEST_ENVIRONMENT` | `development` / `production` | `development` |
| `APPLE_ROOT_CA_PEM` | root CA 路徑（見 `certs/README.md`） | `certs/apple-app-attest-root-ca.pem` |
| `CHALLENGE_TTL_SECONDS` | challenge 有效秒數 | `300` |
| `SQLITE_PATH` | SQLite 檔案路徑 | `var/attest.sqlite` |

設定錯誤（缺 `APP_ID`、讀不到 root CA）會在啟動時直接丟例外。這是刻意的：帶著錯的 App ID 安靜跑起來，症狀是「所有裝置都註冊失敗」，非常難查。

---

## 上線前還要做的事

這個 repo 是參考實作，不是產品。至少還缺：

1. **`src/Http/` 全部換掉** —— 沒有 rate limiting、沒有認證、沒有 CORS。
2. **儲存換掉** —— SQLite 適合單機。challenge 建議 Redis（天生有 TTL），device 放既有資料庫。換的時候**務必保持 `consume()` 的原子語意**。
3. **憑證撤銷檢查** —— 目前不做 CRL / OCSP。
4. **`receipt` 未解析** —— 所以拿不到 Apple 的 fraud metric，也無法做 attestation 的有效期延展。若要做風險評估需另外實作。
5. **challenge 清理** —— `purgeExpired()` 要接上排程。
6. **iOS 端的 TLS cert pinning** —— 屬 client 責任，不在本 repo 範圍。

---

## 參考

- Apple《Validating Apps That Connect to Your Server》
  <https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>
- Apple PKI（下載 Root CA）
  <https://www.apple.com/certificateauthority/private/>
- 設計文件：`docs/superpowers/specs/2026-09-21-app-attest-backend-design.md`
