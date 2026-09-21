<?php

declare(strict_types=1);

namespace AppAttest\Tests\Fixture;

use AppAttest\Cbor\CborEncoder;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * 一台假的 iPhone。
 *
 * 做的事情跟真的 Secure Enclave + App Attest 一樣：產生金鑰、組 authData、
 * 讓「Apple」簽 credCert、用私鑰簽 assertion。差別只在簽發者是
 * FakeAppleCa 而不是真的 Apple。
 *
 * 每個 public 方法都有對應的「壞掉版本」參數，用來製造攻擊場景。測試的
 * 可讀性大半來自這裡：Flaw::NONCE 這種寫法比一堆手動拼位元組好懂得多。
 */
final class FakeDevice
{
    /** WebAuthn flags：bit 0 = User Present，bit 6 = Attested credential data。 */
    private const FLAGS_ATTESTATION = 0x41;
    private const FLAGS_ASSERTION = 0x01;

    private readonly OpenSSLAsymmetricKey $key;

    /** 裝置端自己記的 counter，每簽一次 assertion 加一。 */
    private int $counter = 0;

    public function __construct(
        private readonly string $appId,
        private readonly string $aaguid = 'appattestdevelop',
        private readonly ?FakeAppleCa $ca = null,
    ) {
        $this->key = FakeAppleCa::newEcKey();
    }

    private function ca(): FakeAppleCa
    {
        return $this->ca ?? FakeAppleCa::shared();
    }

    /** 這把金鑰的 keyId（32 bytes raw）。 */
    public function keyId(): string
    {
        return hash('sha256', $this->uncompressedPoint(), true);
    }

    /**
     * 產生一份 attestation。
     *
     * @param string     $challenge server 發的原始 32 bytes
     * @param list<Flaw> $flaws     要注入的瑕疵
     *
     * @return string attestation 的原始位元組（尚未 base64）
     */
    public function attest(string $challenge, array $flaws = []): string
    {
        $has = static fn (Flaw $f): bool => in_array($f, $flaws, true);

        $rpIdHash = $has(Flaw::APP_ID)
            ? hash('sha256', 'WRONGTEAM.com.attacker.app', true)
            : hash('sha256', $this->appId, true);

        $aaguid = $has(Flaw::AAGUID)
            ? "appattest\x00\x00\x00\x00\x00\x00\x00"   // production，但設定是 development
            : $this->aaguid;

        $signCount = $has(Flaw::COUNTER_NOT_ZERO) ? 1 : 0;

        $authData = $rpIdHash
            . chr(self::FLAGS_ATTESTATION)
            . pack('N', $signCount)
            . $aaguid
            . pack('n', 32)
            . $this->keyId()
            . $this->encodeCoseKey();

        // nonce = SHA256(authData ‖ SHA256(challenge))
        $nonce = $has(Flaw::NONCE)
            ? random_bytes(32)                       // 隨機值，一定對不上
            : hash('sha256', $authData . hash('sha256', $challenge, true), true);

        // 憑證鏈本身永遠是有效的 —— BROKEN_CHAIN 的差別在於它接回的是
        // 一個我們不信任的 root。這比「隨便塞垃圾位元組」更接近真實攻擊：
        // 任何人都能開一間 CA 簽出結構完全正確的憑證。
        $signingCa = $has(Flaw::BROKEN_CHAIN) ? FakeAppleCa::rogue() : $this->ca();

        $credCert = $signingCa->signCredCert($this->key, $nonce);
        $x5c = [
            FakeAppleCa::certToDer($credCert),
            $signingCa->intermediateDer,
        ];

        $fmt = $has(Flaw::FMT) ? 'android-safetynet' : 'apple-appattest';

        return CborEncoder::map([
            'fmt' => CborEncoder::text($fmt),
            'attStmt' => CborEncoder::map([
                'x5c' => CborEncoder::arrayOf(array_map(
                    static fn (string $der): string => CborEncoder::bytes($der),
                    $x5c,
                )),
                'receipt' => CborEncoder::bytes('fake-receipt-not-validated'),
            ]),
            'authData' => CborEncoder::bytes($authData),
        ]);
    }

    /**
     * 為一個請求簽 assertion。
     *
     * @param string     $requestHash server 與 client 都算得出來的那個字串
     * @param list<Flaw> $flaws
     *
     * @return string assertion 的原始位元組（尚未 base64）
     */
    public function assert(string $requestHash, array $flaws = []): string
    {
        $has = static fn (Flaw $f): bool => in_array($f, $flaws, true);

        if ($has(Flaw::COUNTER_REPLAY)) {
            // 重送上一次用過的 counter，而不是遞增。
            $signCount = $this->counter;
        } else {
            $signCount = ++$this->counter;
        }

        $rpIdHash = $has(Flaw::APP_ID)
            ? hash('sha256', 'WRONGTEAM.com.attacker.app', true)
            : hash('sha256', $this->appId, true);

        $authenticatorData = $rpIdHash . chr(self::FLAGS_ASSERTION) . pack('N', $signCount);

        $clientDataHash = hash('sha256', $requestHash, true);
        $nonce = hash('sha256', $authenticatorData . $clientDataHash, true);

        if (!openssl_sign($nonce, $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('簽 assertion 失敗：' . openssl_error_string());
        }

        if ($has(Flaw::SIGNATURE)) {
            // 翻掉簽章最後一個 byte。DER 結構還在，但數學上驗不過。
            $signature[strlen($signature) - 1] = chr(ord($signature[strlen($signature) - 1]) ^ 0xFF);
        }

        return CborEncoder::map([
            'signature' => CborEncoder::bytes($signature),
            'authenticatorData' => CborEncoder::bytes($authenticatorData),
        ]);
    }

    /** 未壓縮點格式的公鑰：0x04 ‖ X ‖ Y。 */
    private function uncompressedPoint(): string
    {
        [$x, $y] = $this->coordinates();

        return "\x04" . $x . $y;
    }

    /** COSE_Key 格式的公鑰。 */
    private function encodeCoseKey(): string
    {
        [$x, $y] = $this->coordinates();

        return CborEncoder::map([
            1 => CborEncoder::int(2),        // kty = EC2
            3 => CborEncoder::int(-7),       // alg = ES256
            -1 => CborEncoder::int(1),       // crv = P-256
            -2 => CborEncoder::bytes($x),
            -3 => CborEncoder::bytes($y),
        ]);
    }

    /**
     * 取出公鑰的 x, y 座標，各補滿 32 bytes。
     *
     * OpenSSL 給的座標會去掉前導的 0x00。P-256 的座標必須固定 32 bytes，
     * 少補這個 padding 會讓大約 1/256 的金鑰算出錯的 keyId —— 這種
     * 「大部分時候正常、偶爾失敗」的 bug 最難查。
     *
     * @return array{0: string, 1: string}
     */
    private function coordinates(): array
    {
        $details = openssl_pkey_get_details($this->key);

        if ($details === false || !isset($details['ec']['x'], $details['ec']['y'])) {
            throw new RuntimeException('取不出 EC 座標');
        }

        return [
            str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT),
            str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT),
        ];
    }
}
