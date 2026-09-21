<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Cbor\CborDecoder;
use AppAttest\Cbor\CborException;
use AppAttest\Config;
use AppAttest\RequestHash;
use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;

/**
 * 每次受保護請求的 assertion 驗證。
 *
 * assertion 比 attestation 簡單得多：沒有憑證鏈，只是用註冊時存下來的
 * 公鑰驗一個簽章。但有三個細節錯了就會靜默失效或靜默放行：
 *
 *   1. openssl_verify() 回傳 -1 代表「發生錯誤」，不是「驗證失敗」。
 *      寫成 if (!openssl_verify(...)) 會把 -1 當成通過。必須 === 1。
 *
 *   2. 簽章的訊息是 nonce 這 32 bytes 本身，OpenSSL 會再對它做一次
 *      SHA-256。也就是實際簽的是 SHA256(SHA256(authenticatorData ‖
 *      clientDataHash))。這是 Apple 規範就這樣定的，不是誰寫錯。
 *
 *   3. counter 必須**嚴格**遞增。寫成 >= 會讓同一個 counter 值可以用
 *      無限多次，counter 這道防線等於不存在。
 */
final class AssertionValidator
{
    public function __construct(private readonly Config $config)
    {
    }

    /**
     * @param string $assertionBytes generateAssertion() 的輸出（已 base64 解碼）
     * @param string $publicKeyPem   註冊時存下來的公鑰
     * @param int    $storedCounter  這台裝置目前記錄的 counter
     * @param string $requestHash    server 自己重算出來的 requestHash
     *
     * @return int 新的 counter，呼叫端負責寫回儲存
     *
     * @throws VerificationFailure
     */
    public function validate(
        string $assertionBytes,
        string $publicKeyPem,
        int $storedCounter,
        string $requestHash,
    ): int {
        try {
            $assertion = CborDecoder::decode($assertionBytes);
        } catch (CborException $e) {
            throw VerificationFailure::of(Reason::BAD_CBOR, $e->getMessage());
        }

        if (!is_array($assertion)) {
            throw VerificationFailure::of(Reason::BAD_CBOR, 'assertion 最外層不是 CBOR map');
        }

        $signature = $assertion['signature'] ?? null;
        $authenticatorDataBytes = $assertion['authenticatorData'] ?? null;

        if (!is_string($signature) || !is_string($authenticatorDataBytes)) {
            throw VerificationFailure::of(Reason::BAD_CBOR, 'assertion 缺少 signature 或 authenticatorData');
        }

        $authData = AuthData::parseForAssertion($authenticatorDataBytes);

        // --- 算出被簽的 nonce ---
        //
        // clientData 就是 requestHash 那串 ASCII 字元。requestHash 本身
        // 已經綁定了 method / path / body / challenge（見 RequestHash），
        // 所以簽它等於簽下整個請求。

        $clientDataHash = hash('sha256', $requestHash, true);
        $nonce = hash('sha256', $authenticatorDataBytes . $clientDataHash, true);

        // --- 驗簽章 ---

        $publicKey = openssl_pkey_get_public($publicKeyPem);

        if ($publicKey === false) {
            // 這是伺服器端的問題（存壞的公鑰），不是 client 的錯，但從
            // 安全角度仍然只能拒絕這個請求。
            throw VerificationFailure::of(Reason::SIGNATURE_INVALID, '無法載入已儲存的公鑰');
        }

        // $signature 是 DER 編碼的 ECDSA 簽章，正好是 openssl_verify()
        // 期待的格式，不需要轉換成 raw (r,s)。
        $verifyResult = openssl_verify($nonce, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        if ($verifyResult !== 1) {
            throw VerificationFailure::of(
                Reason::SIGNATURE_INVALID,
                "openssl_verify 回傳 {$verifyResult}（1 才是通過，-1 是執行錯誤）",
            );
        }

        // --- App ID ---
        //
        // 簽章過了還要再驗一次 rpIdHash：簽章只證明「這把金鑰簽的」，
        // 不證明「簽的時候宣告的是我們的 App」。

        if (!hash_equals($this->config->appIdHash(), $authData->rpIdHash)) {
            throw VerificationFailure::of(Reason::APP_ID_MISMATCH, 'assertion 的 rpIdHash 與設定的 APP_ID 不符');
        }

        // --- counter 嚴格遞增 ---

        if ($authData->signCount <= $storedCounter) {
            throw VerificationFailure::of(
                Reason::COUNTER_NOT_INCREASING,
                "signCount 必須大於 {$storedCounter}，實際 {$authData->signCount}",
            );
        }

        return $authData->signCount;
    }

    /**
     * 便利方法：從原始請求重算 requestHash，並與 client 送來的比對。
     *
     * 分成兩步（重算、比對）而不是一步，是為了讓呼叫端沒辦法「忘記重算
     * 而直接信任 header」—— 這個方法根本不接受「client 說的 hash 就是
     * 答案」這種用法。
     *
     * @throws VerificationFailure
     */
    public static function requireMatchingRequestHash(
        string $requestHashFromClient,
        string $method,
        string $path,
        string $body,
        string $challenge,
    ): string {
        $recomputed = RequestHash::compute($method, $path, $body, $challenge);

        if (!RequestHash::matches($requestHashFromClient, $recomputed)) {
            throw VerificationFailure::of(
                Reason::REQUEST_HASH_MISMATCH,
                'header 的 requestHash 與 server 依實際請求重算的結果不符',
            );
        }

        return $recomputed;
    }
}
