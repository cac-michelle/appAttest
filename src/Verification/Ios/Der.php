<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;

/**
 * 最小 DER 讀取器，只夠讀 Apple 那個 nonce extension。
 *
 * DER 的每個元素都是 tag-length-value：
 *
 *   tag     1 byte（我們只處理單一 byte 的 tag，足夠應付這裡的結構）
 *   length  短式：1 byte，值 0-127 即長度本身
 *           長式：第一個 byte 的最高位為 1，低 7 位代表「接下來幾個
 *                 byte 是長度」，之後才是 big-endian 的長度
 *   value   length 個 bytes
 *
 * 故意寫得這麼小：完整的 ASN.1 解析器是個大工程，而我們只需要讀
 * SEQUENCE → [1] → OCTET STRING 這一條路徑。
 */
final class Der
{
    /**
     * 讀一個 TLV，驗證 tag 是否符合預期，回傳 value 並把 offset 往前推。
     *
     * @param int $expectedTag 預期的 tag byte
     *
     * @throws VerificationFailure
     */
    public static function readTlv(string $data, int &$offset, int $expectedTag): string
    {
        if ($offset + 2 > strlen($data)) {
            throw VerificationFailure::of(Reason::NONCE_MISMATCH, 'DER 資料在讀 tag 前就結束了');
        }

        $tag = ord($data[$offset]);

        if ($tag !== $expectedTag) {
            throw VerificationFailure::of(
                Reason::NONCE_MISMATCH,
                sprintf('DER tag 預期 0x%02X，實際 0x%02X', $expectedTag, $tag),
            );
        }

        $offset++;
        $length = self::readLength($data, $offset);

        if ($offset + $length > strlen($data)) {
            throw VerificationFailure::of(Reason::NONCE_MISMATCH, 'DER 長度欄位超出實際資料範圍');
        }

        $value = substr($data, $offset, $length);
        $offset += $length;

        return $value;
    }

    /** @throws VerificationFailure */
    private static function readLength(string $data, int &$offset): int
    {
        $first = ord($data[$offset]);
        $offset++;

        // 短式：最高位為 0，這個 byte 就是長度。
        if ($first < 0x80) {
            return $first;
        }

        // 0x80 本身是 indefinite length，DER 不允許（那是 BER 才有的）。
        if ($first === 0x80) {
            throw VerificationFailure::of(Reason::NONCE_MISMATCH, 'DER 不允許 indefinite length');
        }

        $byteCount = $first & 0x7F;

        // 長度欄位超過 4 bytes 表示長度大於 4GB，這裡不可能出現。
        if ($byteCount > 4 || $offset + $byteCount > strlen($data)) {
            throw VerificationFailure::of(Reason::NONCE_MISMATCH, 'DER 長度欄位不合理');
        }

        $length = 0;

        for ($i = 0; $i < $byteCount; $i++) {
            $length = ($length << 8) | ord($data[$offset]);
            $offset++;
        }

        return $length;
    }
}
