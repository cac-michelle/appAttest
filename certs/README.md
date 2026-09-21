# 信任錨點（Root CA）

驗證 attestation 憑證鏈時唯一的信任來源。**這個檔案放錯，整套驗證就等於沒做。**

## 正式環境

從 Apple 官方下載 **Apple App Attest Root CA**：

<https://www.apple.com/certificateauthority/private/>

下載到的是 DER 格式的 `.cer`，轉成 PEM 後放在這個目錄：

```bash
openssl x509 -inform der -in AppleAppAttestRootCA.cer -out apple-app-attest-root-ca.pem
```

確認一下拿到的是對的東西：

```bash
openssl x509 -in apple-app-attest-root-ca.pem -noout -subject -issuer -dates
```

`subject` 和 `issuer` 應該都是 Apple App Attest Root CA（root 是自簽的，所以兩者相同）。

然後指給服務：

```bash
export APPLE_ROOT_CA_PEM=/path/to/apple-app-attest-root-ca.pem
```

## 注意事項

- **不要**從第三方部落格或 Stack Overflow 複製這份憑證的內容。只從 Apple 的網域下載。
- 憑證檔應該進版控（它是公開資訊，不是機密），這樣部署時才不會因為誰忘了放而靜默失效。
- 服務啟動時如果讀不到這個檔案會直接丟例外而不是繼續跑 —— 這是刻意的，見 `src/Config.php`。

## 測試環境

測試**不使用**這個目錄。`tests/Fixture/FakeAppleCa.php` 會在執行時產生一組自簽的 root + intermediate，並把它傳給 `Config`。

驗證程式碼裡沒有任何一行寫死 Apple —— 信任錨點完全由設定決定。所以測試跑的是正式環境會執行的同一段邏輯，差別只在信任誰。
