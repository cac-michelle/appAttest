<?php

declare(strict_types=1);

namespace AppAttest\Tests\Unit;

use AppAttest\Cbor\CborDecoder;
use AppAttest\Cbor\CborEncoder;
use AppAttest\Cbor\CborException;
use PHPUnit\Framework\TestCase;

/**
 * CBOR 解碼器解的是攻擊者完全可控的位元組，所以「拒絕什麼」比
 * 「接受什麼」更重要。
 */
final class CborDecoderTest extends TestCase
{
    public function testDecodesSmallUnsignedInt(): void
    {
        self::assertSame(0, CborDecoder::decode("\x00"));
        self::assertSame(23, CborDecoder::decode("\x17"));
    }

    public function testDecodesMultiByteUnsignedInt(): void
    {
        self::assertSame(24, CborDecoder::decode("\x18\x18"));
        self::assertSame(256, CborDecoder::decode("\x19\x01\x00"));
        self::assertSame(65536, CborDecoder::decode("\x1a\x00\x01\x00\x00"));
    }

    /** COSE_Key 用負整數當 key（-1 = crv、-2 = x、-3 = y）。 */
    public function testDecodesNegativeInt(): void
    {
        self::assertSame(-1, CborDecoder::decode("\x20"));
        self::assertSame(-7, CborDecoder::decode("\x26"));
    }

    public function testDecodesByteAndTextStrings(): void
    {
        self::assertSame("\x01\x02\x03", CborDecoder::decode(CborEncoder::bytes("\x01\x02\x03")));
        self::assertSame('apple-appattest', CborDecoder::decode(CborEncoder::text('apple-appattest')));
    }

    public function testRoundTripsNestedStructure(): void
    {
        $encoded = CborEncoder::map([
            'fmt' => CborEncoder::text('apple-appattest'),
            'attStmt' => CborEncoder::map([
                'x5c' => CborEncoder::arrayOf([
                    CborEncoder::bytes('cert-one'),
                    CborEncoder::bytes('cert-two'),
                ]),
            ]),
            'authData' => CborEncoder::bytes('auth'),
        ]);

        self::assertSame([
            'fmt' => 'apple-appattest',
            'attStmt' => ['x5c' => ['cert-one', 'cert-two']],
            'authData' => 'auth',
        ], CborDecoder::decode($encoded));
    }

    /** 結尾多餘的位元組代表有人在夾帶東西。 */
    public function testTrailingBytesAreRejected(): void
    {
        $this->expectException(CborException::class);

        CborDecoder::decode("\x00\xFF");
    }

    /** indefinite-length 會讓長度檢查失去意義，一律拒絕。 */
    public function testIndefiniteLengthIsRejected(): void
    {
        $this->expectException(CborException::class);

        // 0x5F = byte string, indefinite length
        CborDecoder::decode("\x5F\x41\x01\xFF");
    }

    /** 宣告的長度超過實際資料 → 不可以讀出界。 */
    public function testTruncatedInputIsRejected(): void
    {
        $this->expectException(CborException::class);

        // 宣告 10 bytes 的 byte string，但只給 2 bytes
        CborDecoder::decode("\x4A\x01\x02");
    }

    /** 宣告天文數字的 map 長度不該讓我們白跑迴圈或配置記憶體。 */
    public function testAbsurdMapLengthIsRejectedImmediately(): void
    {
        $this->expectException(CborException::class);

        // map，宣告 0xFFFFFFFF 個 entry，後面什麼都沒有
        CborDecoder::decode("\xBA\xFF\xFF\xFF\xFF");
    }

    /** tag / float / simple value 不會出現在合法的 attestation 裡。 */
    public function testUnsupportedMajorTypesAreRejected(): void
    {
        $this->expectException(CborException::class);

        CborDecoder::decode("\xC0\x00");   // major type 6 = tag
    }

    public function testFloatIsRejected(): void
    {
        $this->expectException(CborException::class);

        CborDecoder::decode("\xF9\x00\x00");   // half-precision float
    }

    /** 重複的 key 是 ill-formed，不要讓「誰蓋誰」變成驗證結果的差異。 */
    public function testDuplicateMapKeysAreRejected(): void
    {
        $this->expectException(CborException::class);

        // {1: 1, 1: 2}
        CborDecoder::decode("\xA2\x01\x01\x01\x02");
    }

    /** 深度過深不該炸掉 stack。 */
    public function testDeeplyNestedInputIsRejected(): void
    {
        $this->expectException(CborException::class);

        // 每個 \x81 是「長度 1 的 array」，疊 50 層
        CborDecoder::decode(str_repeat("\x81", 50) . "\x00");
    }

    /** decodePrefix 回報消耗長度，讓呼叫端能確認沒有多餘位元組。 */
    public function testDecodePrefixReportsConsumedLength(): void
    {
        $encoded = CborEncoder::map([1 => CborEncoder::int(2)]);

        [$value, $consumed] = CborDecoder::decodePrefix($encoded . 'TRAILING');

        self::assertSame([1 => 2], $value);
        self::assertSame(strlen($encoded), $consumed);
    }
}
