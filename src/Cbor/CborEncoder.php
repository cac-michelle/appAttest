<?php

declare(strict_types=1);

namespace AppAttest\Cbor;

use InvalidArgumentException;

/**
 * 最小 CBOR 編碼器。
 *
 * **正式後端用不到這個檔案** —— 後端只解碼，不編碼。它存在的唯一理由是
 * 讓測試夾具（tests/Fixture/FakeDevice.php）能造出假的 attestation 與
 * assertion，你們照搬程式碼時可以略過 src/Cbor/CborEncoder.php。
 *
 * 只支援 CborDecoder 接受的同一個子集，且一律用 definite-length。
 */
final class CborEncoder
{
    /** 編碼無號整數或負整數。 */
    public static function int(int $value): string
    {
        if ($value >= 0) {
            return self::head(0, $value);
        }

        return self::head(1, -1 - $value);
    }

    /** 編碼 byte string（major type 2）。 */
    public static function bytes(string $value): string
    {
        return self::head(2, strlen($value)) . $value;
    }

    /** 編碼 text string（major type 3）。 */
    public static function text(string $value): string
    {
        return self::head(3, strlen($value)) . $value;
    }

    /**
     * 編碼 array。元素必須已經是編碼過的 CBOR 位元組。
     *
     * @param list<string> $encodedItems
     */
    public static function arrayOf(array $encodedItems): string
    {
        return self::head(4, count($encodedItems)) . implode('', $encodedItems);
    }

    /**
     * 編碼 map。key 是 PHP 的 int 或 string，value 必須已經是編碼過的
     * CBOR 位元組 —— 這樣呼叫端才能精準控制每個值的型別（例如區分
     * byte string 與 text string）。
     *
     * @param array<int|string, string> $encodedEntries
     */
    public static function map(array $encodedEntries): string
    {
        $out = self::head(5, count($encodedEntries));

        foreach ($encodedEntries as $key => $encodedValue) {
            $out .= is_int($key) ? self::int($key) : self::text($key);
            $out .= $encodedValue;
        }

        return $out;
    }

    /** 組出 major type + 長度/值 的前導位元組。 */
    private static function head(int $majorType, int $value): string
    {
        if ($value < 0) {
            throw new InvalidArgumentException('CBOR head 的值不能為負');
        }

        if ($value < 24) {
            return chr(($majorType << 5) | $value);
        }

        if ($value <= 0xFF) {
            return chr(($majorType << 5) | 24) . chr($value);
        }

        if ($value <= 0xFFFF) {
            return chr(($majorType << 5) | 25) . pack('n', $value);
        }

        if ($value <= 0xFFFFFFFF) {
            return chr(($majorType << 5) | 26) . pack('N', $value);
        }

        return chr(($majorType << 5) | 27) . pack('J', $value);
    }
}
