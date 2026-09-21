<?php

declare(strict_types=1);

namespace AppAttest\Tests\Unit;

use AppAttest\Verification\Ios\CoseKey;
use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;
use PHPUnit\Framework\TestCase;

/**
 * COSE_Key → PEM 的轉換（PHP 沒有現成 API 的那一段）。
 */
final class CoseKeyTest extends TestCase
{
    /** 固定的 x/y 一定要產生固定的 PEM —— 手工組 DER 就是為了這個。 */
    public function testKnownCoordinatesProduceLoadablePem(): void
    {
        $x = str_repeat("\x11", 32);
        $y = str_repeat("\x22", 32);

        $pem = CoseKey::fromCoseMap($this->coseMap($x, $y))->toPem();

        self::assertStringStartsWith("-----BEGIN PUBLIC KEY-----\n", $pem);
        self::assertStringEndsWith("-----END PUBLIC KEY-----\n", $pem);
    }

    /**
     * 真正的驗收標準：OpenSSL 載得進去，而且認出它是 P-256。
     *
     * 用真的 EC 金鑰的座標來測，因為隨便填的 x/y 不在曲線上，
     * OpenSSL 可能會拒絕。
     */
    public function testRealCoordinatesRoundTripThroughOpenSsl(): void
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        self::assertNotFalse($key);

        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);

        $x = str_pad($details['ec']['x'], 32, "\x00", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\x00", STR_PAD_LEFT);

        $pem = CoseKey::fromCoseMap($this->coseMap($x, $y))->toPem();
        $loaded = openssl_pkey_get_public($pem);

        self::assertNotFalse($loaded, '組出來的 PEM 必須能被 OpenSSL 載入');

        $loadedDetails = openssl_pkey_get_details($loaded);
        self::assertSame(OPENSSL_KEYTYPE_EC, $loadedDetails['type']);
        self::assertSame('prime256v1', $loadedDetails['ec']['curve_name']);
        self::assertSame($details['key'], $loadedDetails['key'], '重組出來的公鑰要跟原本的一致');
    }

    /** keyId = SHA256(0x04 ‖ X ‖ Y)。 */
    public function testKeyIdIsSha256OfUncompressedPoint(): void
    {
        $x = str_repeat("\x11", 32);
        $y = str_repeat("\x22", 32);

        $coseKey = CoseKey::fromCoseMap($this->coseMap($x, $y));

        self::assertSame(hash('sha256', "\x04" . $x . $y, true), $coseKey->keyId());
        self::assertSame(32, strlen($coseKey->keyId()));
    }

    public function testWrongKeyTypeIsRejected(): void
    {
        $map = $this->coseMap(str_repeat("\x11", 32), str_repeat("\x22", 32));
        $map[1] = 3;   // OKP 而不是 EC2

        $this->expectFailure();

        CoseKey::fromCoseMap($map);
    }

    /** 不接受「宣告了別的演算法」的公鑰。 */
    public function testWrongAlgorithmIsRejected(): void
    {
        $map = $this->coseMap(str_repeat("\x11", 32), str_repeat("\x22", 32));
        $map[3] = -257;   // RS256

        $this->expectFailure();

        CoseKey::fromCoseMap($map);
    }

    public function testWrongCurveIsRejected(): void
    {
        $map = $this->coseMap(str_repeat("\x11", 32), str_repeat("\x22", 32));
        $map[-1] = 2;   // P-384

        $this->expectFailure();

        CoseKey::fromCoseMap($map);
    }

    public function testMissingAlgorithmIsRejected(): void
    {
        $map = $this->coseMap(str_repeat("\x11", 32), str_repeat("\x22", 32));
        unset($map[3]);

        $this->expectFailure();

        CoseKey::fromCoseMap($map);
    }

    /** 座標長度不對 → 拒絕（不要自動補零，那會掩蓋問題）。 */
    public function testShortCoordinateIsRejected(): void
    {
        $this->expectFailure();

        CoseKey::fromCoseMap($this->coseMap(str_repeat("\x11", 31), str_repeat("\x22", 32)));
    }

    public function testEmptyMapIsRejected(): void
    {
        $this->expectFailure();

        CoseKey::fromCoseMap([]);
    }

    /** @return array<int, mixed> */
    private function coseMap(string $x, string $y): array
    {
        return [
            1 => 2,      // kty = EC2
            3 => -7,     // alg = ES256
            -1 => 1,     // crv = P-256
            -2 => $x,
            -3 => $y,
        ];
    }

    private function expectFailure(): void
    {
        $this->expectException(VerificationFailure::class);
        $this->expectExceptionMessageMatches('/^' . Reason::BAD_COSE_KEY->value . '/');
    }
}
