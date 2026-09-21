<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;

/**
 * 把 attestation 裡的 COSE_Key 轉成 OpenSSL 能用的公鑰。
 *
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ PHP 特有的坑：沒有「從 x, y 座標建 EC 公鑰」的 API。             │
 * │ Python / Node / Java 都是一行呼叫，PHP 得自己組 DER。            │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * COSE_Key（RFC 8152）是一個 CBOR map，整數當 key：
 *
 *    key  名稱  App Attest 的值
 *    ---  ----  ----------------------------------
 *      1  kty   2   = EC2（橢圓曲線，雙座標）
 *      3  alg   -7  = ES256（ECDSA + SHA-256）
 *     -1  crv   1   = P-256 (secp256r1 / prime256v1)
 *     -2  x     32 bytes
 *     -3  y     32 bytes
 *
 * 這些值全部都要檢查。不檢查 alg 而直接拿 x/y 去用，等於接受任何
 * 攻擊者宣告的演算法。
 */
final class CoseKey
{
    // COSE_Key 的 map key
    private const KEY_KTY = 1;
    private const KEY_ALG = 3;
    private const KEY_CRV = -1;
    private const KEY_X = -2;
    private const KEY_Y = -3;

    // App Attest 唯一合法的組合
    private const KTY_EC2 = 2;
    private const ALG_ES256 = -7;
    private const CRV_P256 = 1;

    private const COORDINATE_LENGTH = 32;

    /**
     * P-256 公鑰的 SubjectPublicKeyInfo DER 固定前綴。
     *
     * 逐段拆解（這 26 bytes 對所有 P-256 公鑰都一樣，不必動態產生）：
     *
     *   30 59                          SEQUENCE，長度 0x59 = 89
     *     30 13                        SEQUENCE，長度 0x13 = 19（AlgorithmIdentifier）
     *       06 07 2A8648CE3D0201       OID 1.2.840.10045.2.1  = id-ecPublicKey
     *       06 08 2A8648CE3D030107     OID 1.2.840.10045.3.1.7 = prime256v1
     *     03 42 00                     BIT STRING，長度 0x42 = 66，0 個未使用位元
     *       04 <X:32> <Y:32>           未壓縮點格式（0x04 開頭）
     *
     * 長度算術：19 + 2 + 3 + 65 = 89 ✓（跟外層宣告的 0x59 相符）
     */
    private const P256_SPKI_PREFIX_HEX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    private function __construct(
        public readonly string $x,
        public readonly string $y,
    ) {
    }

    /**
     * 從 authData 解出的 COSE map 建立公鑰，並驗證所有演算法參數。
     *
     * @param array<int|string, mixed> $map
     *
     * @throws VerificationFailure
     */
    public static function fromCoseMap(array $map): self
    {
        $kty = $map[self::KEY_KTY] ?? null;
        $alg = $map[self::KEY_ALG] ?? null;
        $crv = $map[self::KEY_CRV] ?? null;
        $x = $map[self::KEY_X] ?? null;
        $y = $map[self::KEY_Y] ?? null;

        if ($kty !== self::KTY_EC2) {
            throw VerificationFailure::of(Reason::BAD_COSE_KEY, 'kty 必須是 2 (EC2)');
        }

        if ($alg !== self::ALG_ES256) {
            // 不接受「沒有 alg」或其他演算法。Secure Enclave 的 App Attest
            // 金鑰一定是 ES256，出現別的值代表這不是我們預期的東西。
            throw VerificationFailure::of(Reason::BAD_COSE_KEY, 'alg 必須是 -7 (ES256)');
        }

        if ($crv !== self::CRV_P256) {
            throw VerificationFailure::of(Reason::BAD_COSE_KEY, 'crv 必須是 1 (P-256)');
        }

        if (!is_string($x) || strlen($x) !== self::COORDINATE_LENGTH) {
            throw VerificationFailure::of(Reason::BAD_COSE_KEY, 'x 座標必須是 32 bytes');
        }

        if (!is_string($y) || strlen($y) !== self::COORDINATE_LENGTH) {
            throw VerificationFailure::of(Reason::BAD_COSE_KEY, 'y 座標必須是 32 bytes');
        }

        return new self($x, $y);
    }

    /**
     * 未壓縮點格式：0x04 ‖ X ‖ Y，共 65 bytes。
     *
     * keyId 就是這 65 bytes 的 SHA-256。
     */
    public function uncompressedPoint(): string
    {
        return "\x04" . $this->x . $this->y;
    }

    /**
     * 這把公鑰對應的 keyId（32 bytes raw）。
     *
     * Apple 的定義：keyId = SHA256(未壓縮點格式的公鑰)。
     * 驗證時要確認它同時等於 client 送來的 keyId，以及 authData 裡的
     * credentialId。
     */
    public function keyId(): string
    {
        return hash('sha256', $this->uncompressedPoint(), true);
    }

    /**
     * 組出 PEM 格式的公鑰，可直接餵給 openssl_pkey_get_public()。
     */
    public function toPem(): string
    {
        $der = hex2bin(self::P256_SPKI_PREFIX_HEX) . $this->uncompressedPoint();

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }
}
