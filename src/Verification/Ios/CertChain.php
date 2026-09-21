<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;

/**
 * 驗證 attestation 的憑證鏈：credCert ← intermediate ← root CA。
 *
 * 這一步證明的是「這把金鑰真的由 Apple 的硬體產生」。信任錨點是設定檔
 * 指定的 root CA —— 正式環境放 Apple App Attest Root CA，測試放夾具產生的
 * 自簽 CA。**同一份驗證邏輯，只換信任錨點**，所以測試涵蓋到的就是正式
 * 環境會跑的那段程式碼。
 *
 * === 為什麼手動逐層驗，而不用 openssl_x509_checkpurpose() ===
 *
 * 那個函式需要一個 CA 檔案或目錄，而且會連帶檢查 purpose / EKU，對
 * App Attest 的憑證不適用。這裡的鏈固定只有三層，手動驗反而更清楚，
 * 也更容易看懂每一步在檢查什麼。
 *
 * === 不做的事 ===
 *
 * 不檢查憑證撤銷（CRL / OCSP）。Apple 沒有為 App Attest 的 credCert
 * 提供撤銷機制，intermediate 的撤銷則屬於極罕見事件。正式環境若要更
 * 嚴謹，可以定期檢查 intermediate 的狀態。
 */
final class CertChain
{
    /**
     * @param list<string> $derCerts attStmt.x5c，[0] 是 credCert，[1] 是 intermediate
     * @param string       $rootCaPem 信任錨點
     * @param int          $now       Unix timestamp，用來檢查有效期
     *
     * @return string 驗證通過的 credCert，PEM 格式
     *
     * @throws VerificationFailure
     */
    public static function verify(array $derCerts, string $rootCaPem, int $now): string
    {
        if (count($derCerts) !== 2) {
            // Apple 的 x5c 固定是 [credCert, intermediateCert]。不接受更長的
            // 鏈：多出來的憑證只可能是攻擊者想塞進來的中間層。
            throw VerificationFailure::of(
                Reason::CERT_CHAIN_INVALID,
                sprintf('x5c 應含 2 張憑證，實際 %d 張', count($derCerts)),
            );
        }

        foreach ($derCerts as $i => $der) {
            if (!is_string($der) || $der === '') {
                throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, "x5c[{$i}] 不是位元組字串");
            }
        }

        $credCertPem = self::derToPem($derCerts[0]);
        $intermediatePem = self::derToPem($derCerts[1]);

        // 三張憑證都必須在有效期內。過期的 intermediate 代表這份
        // attestation 來自我們不該再信任的時間點。
        self::assertWithinValidity($credCertPem, $now, 'credCert');
        self::assertWithinValidity($intermediatePem, $now, 'intermediate');
        self::assertWithinValidity($rootCaPem, $now, 'root CA');

        // intermediate 必須是 CA。少了這個檢查，攻擊者可以拿一張合法的
        // 葉憑證（非 CA）去簽自己的 credCert，鏈在數學上依然成立。
        self::assertIsCa($intermediatePem, 'intermediate');
        self::assertIsCa($rootCaPem, 'root CA');

        self::assertSignedBy($intermediatePem, $rootCaPem, 'intermediate ← root CA');
        self::assertSignedBy($credCertPem, $intermediatePem, 'credCert ← intermediate');

        return $credCertPem;
    }

    /** 把裸 DER 包成 PEM。CBOR 裡的 x5c 給的是 DER。 */
    public static function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END CERTIFICATE-----\n";
    }

    /** @throws VerificationFailure */
    private static function assertSignedBy(string $certPem, string $issuerPem, string $label): void
    {
        $issuerPublicKey = openssl_pkey_get_public($issuerPem);

        if ($issuerPublicKey === false) {
            throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, "取不出簽發者公鑰（{$label}）");
        }

        $result = openssl_x509_verify($certPem, $issuerPublicKey);

        // openssl_x509_verify() 回傳 1 成功、0 失敗、-1 錯誤。
        // 一定要 === 1；寫成 if (!$result) 會把 -1 當成通過。
        if ($result !== 1) {
            throw VerificationFailure::of(
                Reason::CERT_CHAIN_INVALID,
                "簽章驗證失敗（{$label}），openssl_x509_verify 回傳 {$result}",
            );
        }
    }

    /** @throws VerificationFailure */
    private static function assertWithinValidity(string $certPem, int $now, string $label): void
    {
        $parsed = openssl_x509_parse($certPem);

        if ($parsed === false) {
            throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, "無法解析憑證（{$label}）");
        }

        $from = $parsed['validFrom_time_t'] ?? null;
        $to = $parsed['validTo_time_t'] ?? null;

        if (!is_int($from) || !is_int($to)) {
            throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, "憑證缺少有效期欄位（{$label}）");
        }

        if ($now < $from || $now > $to) {
            throw VerificationFailure::of(
                Reason::CERT_EXPIRED,
                sprintf('%s 不在有效期內（%d ~ %d，現在 %d）', $label, $from, $to, $now),
            );
        }
    }

    /** @throws VerificationFailure */
    private static function assertIsCa(string $certPem, string $label): void
    {
        $parsed = openssl_x509_parse($certPem);

        if ($parsed === false) {
            throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, "無法解析憑證（{$label}）");
        }

        $basicConstraints = $parsed['extensions']['basicConstraints'] ?? '';

        if (!is_string($basicConstraints) || !str_contains($basicConstraints, 'CA:TRUE')) {
            throw VerificationFailure::of(Reason::CERT_CHAIN_INVALID, "{$label} 不是 CA 憑證");
        }
    }
}
