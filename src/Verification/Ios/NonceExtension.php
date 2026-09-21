<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;

/**
 * 從 credCert 取出 Apple 埋進去的 nonce。
 *
 * === 這是整個註冊驗證的核心 ===
 *
 * Apple 在簽發 credCert 時，把 SHA256(authData ‖ SHA256(challenge)) 寫進
 * 一個自訂的憑證 extension。因為這個值是被 Apple 的 CA 簽名保護的，所以：
 *
 *   - 我們發出的 challenge 確實有被送進 Secure Enclave（不是攻擊者自己編的）
 *   - 那份 authData（含公鑰）確實是 Apple 在同一次操作裡產生的
 *
 * 換句話說，這一個檢查同時綁定了「這次的 challenge」和「這把金鑰」。
 * 少了它，攻擊者可以拿舊的 attestation 重放。
 *
 * extension 的內容是這樣的 DER：
 *
 *   30 24              SEQUENCE，長度 0x24 = 36
 *      A1 22           [1] context-specific, constructed，長度 0x22 = 34
 *         04 20        OCTET STRING，長度 0x20 = 32
 *            <32 bytes nonce>
 *
 * 總長 38 bytes。
 *
 * 註：拿最後 32 bytes 也「能動」，但那是靠結構碰巧固定。這裡照結構解，
 * 格式不符就拒絕 —— 驗證程式碼不該賭輸入的形狀。
 */
final class NonceExtension
{
    /** Apple 的自訂 OID。OpenSSL 不認得它，所以會以原始 DER 回傳。 */
    public const OID = '1.2.840.113635.100.8.2';

    private const NONCE_LENGTH = 32;

    // DER tag
    private const TAG_SEQUENCE = 0x30;
    private const TAG_CONTEXT_1_CONSTRUCTED = 0xA1;
    private const TAG_OCTET_STRING = 0x04;

    /**
     * 從憑證的 PEM 取出 nonce（32 bytes raw）。
     *
     * @throws VerificationFailure extension 不存在或格式不符
     */
    public static function extract(string $certPem): string
    {
        $parsed = openssl_x509_parse($certPem);

        if ($parsed === false) {
            throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, '無法解析 credCert');
        }

        // OpenSSL 認得的 extension 會以名稱當 key（例如 basicConstraints），
        // 認不得的則以 OID 字串當 key，值是未經處理的原始 DER。
        $raw = $parsed['extensions'][self::OID] ?? null;

        if (!is_string($raw) || $raw === '') {
            throw VerificationFailure::of(
                Reason::NONCE_MISMATCH,
                'credCert 沒有 Apple nonce extension ' . self::OID,
            );
        }

        $offset = 0;
        $sequence = Der::readTlv($raw, $offset, self::TAG_SEQUENCE);

        if ($offset !== strlen($raw)) {
            throw VerificationFailure::of(Reason::NONCE_MISMATCH, 'nonce extension 結尾有多餘位元組');
        }

        $inner = 0;
        $context = Der::readTlv($sequence, $inner, self::TAG_CONTEXT_1_CONSTRUCTED);

        $octet = 0;
        $nonce = Der::readTlv($context, $octet, self::TAG_OCTET_STRING);

        if (strlen($nonce) !== self::NONCE_LENGTH) {
            throw VerificationFailure::of(
                Reason::NONCE_MISMATCH,
                sprintf('nonce 應為 %d bytes，實際 %d', self::NONCE_LENGTH, strlen($nonce)),
            );
        }

        return $nonce;
    }
}
