<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Cbor\CborDecoder;
use AppAttest\Cbor\CborException;
use AppAttest\Config;
use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;

/**
 * 註冊時的 attestation 驗證 —— Apple 規範的七項檢查。
 *
 * 參考：Apple《Validating Apps That Connect to Your Server》
 * https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
 *
 * 一份 attestation 同時證明兩件事：這是正版未被竄改的 App，而且它跑在
 * 真正的 Apple 硬體上。七項檢查缺一不可 —— 每一項都對應一種攻擊：
 *
 *   1. fmt          擋掉餵進其他格式的 attestation
 *   2. 憑證鏈        擋掉自己造的假金鑰（不是 Secure Enclave 產生的）
 *   3. nonce        擋掉重放舊的 attestation
 *   4. keyId        擋掉「宣告的公鑰」與「實際被 Apple 簽的公鑰」不一致
 *   5. App ID       擋掉別人的 App 拿自己合法的 attestation 來用
 *   6. counter == 0 擋掉拿 assertion 的 authData 冒充 attestation
 *   7. aaguid       擋掉開發版 App 存取正式環境
 */
final class AttestationValidator
{
    private const EXPECTED_FMT = 'apple-appattest';

    public function __construct(private readonly Config $config)
    {
    }

    /**
     * @param string $attestationBytes attestKey() 的輸出（已 base64 解碼）
     * @param string $keyIdFromClient  client 宣告的 keyId，32 bytes raw
     * @param string $challenge        我們發出的 challenge，原始 32 bytes
     * @param int    $now              Unix timestamp
     *
     * @throws VerificationFailure 任何一項檢查未通過
     */
    public function validate(
        string $attestationBytes,
        string $keyIdFromClient,
        string $challenge,
        int $now,
    ): ValidatedAttestation {
        // --- 解開外層 CBOR ---

        try {
            $attestation = CborDecoder::decode($attestationBytes);
        } catch (CborException $e) {
            throw VerificationFailure::of(Reason::BAD_CBOR, $e->getMessage());
        }

        if (!is_array($attestation)) {
            throw VerificationFailure::of(Reason::BAD_CBOR, 'attestation 最外層不是 CBOR map');
        }

        // --- 檢查 1：fmt ---

        $fmt = $attestation['fmt'] ?? null;

        if ($fmt !== self::EXPECTED_FMT) {
            throw VerificationFailure::of(Reason::BAD_FMT, 'fmt 必須是 ' . self::EXPECTED_FMT);
        }

        $attStmt = $attestation['attStmt'] ?? null;
        $authDataBytes = $attestation['authData'] ?? null;

        if (!is_array($attStmt) || !is_string($authDataBytes)) {
            throw VerificationFailure::of(Reason::BAD_CBOR, 'attestation 缺少 attStmt 或 authData');
        }

        $x5c = $attStmt['x5c'] ?? null;

        if (!is_array($x5c)) {
            throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, 'attStmt 缺少 x5c');
        }

        $authData = AuthData::parseForAttestation($authDataBytes);

        // --- 檢查 2：憑證鏈 credCert ← intermediate ← root CA ---

        $credCertPem = CertChain::verify(array_values($x5c), $this->config->rootCaPem, $now);

        // --- 檢查 3：nonce ---
        //
        // clientDataHash = SHA256(challenge)
        // nonce          = SHA256(authData ‖ clientDataHash)
        //
        // 這個值必須等於 Apple 寫進 credCert extension 的值。因為
        // extension 受 Apple 的簽章保護，攻擊者改不了。

        $clientDataHash = hash('sha256', $challenge, true);
        $expectedNonce = hash('sha256', $authDataBytes . $clientDataHash, true);
        $nonceFromCert = NonceExtension::extract($credCertPem);

        if (!hash_equals($expectedNonce, $nonceFromCert)) {
            throw VerificationFailure::of(Reason::NONCE_MISMATCH, 'credCert 裡的 nonce 與重算結果不符');
        }

        // --- 檢查 4：keyId ---
        //
        // keyId 必須同時等於：
        //   (a) 公鑰的 SHA-256
        //   (b) client 在 request 裡宣告的 keyId
        //   (c) authData 裡的 credentialId
        //
        // 三者比對是為了確保「我們待會兒存起來的公鑰」就是「Apple 簽的
        // 那一把」，中間沒有被掉包。

        $coseKey = CoseKey::fromCoseMap($authData->coseKeyMap ?? []);
        $derivedKeyId = $coseKey->keyId();

        if (!hash_equals($derivedKeyId, $keyIdFromClient)) {
            throw VerificationFailure::of(Reason::KEY_ID_MISMATCH, 'client 宣告的 keyId 與公鑰不符');
        }

        if (!hash_equals($derivedKeyId, (string) $authData->credentialId)) {
            throw VerificationFailure::of(Reason::KEY_ID_MISMATCH, 'authData 的 credentialId 與公鑰不符');
        }

        // --- 檢查 5：App ID ---

        if (!hash_equals($this->config->appIdHash(), $authData->rpIdHash)) {
            throw VerificationFailure::of(Reason::APP_ID_MISMATCH, 'rpIdHash 與設定的 APP_ID 不符');
        }

        // --- 檢查 6：counter 必須為 0 ---
        //
        // 一把新註冊的金鑰從未簽過任何 assertion。不為 0 表示這不是一份
        // 全新的 attestation。

        if ($authData->signCount !== 0) {
            throw VerificationFailure::of(
                Reason::COUNTER_NOT_ZERO,
                "註冊時 signCount 應為 0，實際 {$authData->signCount}",
            );
        }

        // --- 檢查 7：環境（aaguid）---

        if (!hash_equals($this->config->expectedAaguid(), (string) $authData->aaguid)) {
            throw VerificationFailure::of(
                Reason::AAGUID_MISMATCH,
                sprintf(
                    'aaguid 不符：設定為 %s，attestation 來自 %s',
                    $this->config->environment,
                    self::describeAaguid((string) $authData->aaguid),
                ),
            );
        }

        return new ValidatedAttestation($coseKey->toPem(), $derivedKeyId);
    }

    /** 把 aaguid 轉成 log 看得懂的字串。 */
    private static function describeAaguid(string $aaguid): string
    {
        return match ($aaguid) {
            'appattestdevelop' => 'development',
            "appattest\x00\x00\x00\x00\x00\x00\x00" => 'production',
            default => 'unknown(' . bin2hex($aaguid) . ')',
        };
    }
}
