<?php

declare(strict_types=1);

namespace AppAttest\Cbor;

/**
 * 嚴格的最小 CBOR 解碼器（RFC 8949 的子集）。
 *
 * === 為什麼不用現成的 CBOR 套件 ===
 *
 * 兩個理由：
 *
 * 1. 這個 repo 是要給你們複製進自己專案的參考實作。零 composer 相依表示
 *    你們不用為了驗 attestation 而跟團隊爭取新套件。
 *
 * 2. App Attest 的 attestation 只用到 CBOR 的一小塊：definite-length 的
 *    map / array / byte string / text string / 整數。**只接受這個子集、
 *    其餘一律拒絕**，比接上一個什麼都支援的泛用解碼器更安全 —— 因為這裡
 *    解的是攻擊者可以完全控制的位元組。
 *
 * 明確拒絕的東西（全部都不該出現在合法的 attestation 裡）：
 *   - indefinite-length（additional info = 31）：會讓長度檢查失去意義
 *   - tag（major type 6）、float / simple value（major type 7）
 *   - 結尾多餘的位元組：一份 attestation 必須剛好用完，多出來的就是可疑
 *   - 超過深度上限的巢狀結構：避免遞迴炸掉 stack
 *
 * 如果你們偏好用套件，把這個類別換成 spomky-labs/cbor-php 即可，
 * 對外只有 decode() 一個進入點，其餘程式碼不受影響。
 *
 * byte string 與 text string 解出來都是 PHP string。App Attest 用不到
 * 兩者的區分（key 一定是 text、payload 一定是 bytes），所以不另外包裝。
 */
final class CborDecoder
{
    /** 巢狀深度上限。真實的 attestation 只有 3 層左右。 */
    private const MAX_DEPTH = 16;

    private int $offset = 0;

    private function __construct(private readonly string $data)
    {
    }

    /**
     * 解碼一個完整的 CBOR 值，並要求輸入剛好用完。
     *
     * @throws CborException 格式不符、有多餘位元組、或用到不支援的型別
     */
    public static function decode(string $data): mixed
    {
        $decoder = new self($data);
        $value = $decoder->readValue(0);

        if ($decoder->offset !== strlen($data)) {
            throw new CborException(sprintf(
                'CBOR 值結束後還有 %d 個多餘位元組',
                strlen($data) - $decoder->offset,
            ));
        }

        return $value;
    }

    /**
     * 解碼一個 CBOR 值，允許後面還有資料，並回報消耗了多少位元組。
     *
     * authData 需要這個：COSE 公鑰位在 authData 尾端，我們要確認它
     * 「剛好」佔滿剩下的空間，不多不少。
     *
     * @return array{0: mixed, 1: int} [解出的值, 消耗的位元組數]
     */
    public static function decodePrefix(string $data): array
    {
        $decoder = new self($data);
        $value = $decoder->readValue(0);

        return [$value, $decoder->offset];
    }

    private function readValue(int $depth): mixed
    {
        if ($depth > self::MAX_DEPTH) {
            throw new CborException('CBOR 巢狀層數超過上限 ' . self::MAX_DEPTH);
        }

        $initialByte = ord($this->take(1));
        $majorType = $initialByte >> 5;
        $additionalInfo = $initialByte & 0x1F;

        return match ($majorType) {
            0 => $this->readUnsigned($additionalInfo),
            1 => $this->readNegative($additionalInfo),
            2, 3 => $this->take($this->readLength($additionalInfo)),
            4 => $this->readArray($additionalInfo, $depth),
            5 => $this->readMap($additionalInfo, $depth),
            default => throw new CborException(
                "不支援的 CBOR major type {$majorType}（App Attest 不會用到 tag / float / simple value）",
            ),
        };
    }

    /** major type 0：無號整數。 */
    private function readUnsigned(int $additionalInfo): int
    {
        if ($additionalInfo < 24) {
            return $additionalInfo;
        }

        $byteCount = match ($additionalInfo) {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            // 28-30 是保留值，31 是 indefinite-length —— 兩者都拒絕。
            default => throw new CborException("不支援的 additional info {$additionalInfo}"),
        };

        $bytes = $this->take($byteCount);
        $value = 0;

        foreach (str_split($bytes) as $byte) {
            // PHP 的 int 是有號 64 位元，所以 8 bytes 的 CBOR 整數最高位
            // 若為 1 就會溢位成負數。先擋下來，不要讓它靜默變成錯的值。
            if ($value > (PHP_INT_MAX >> 8)) {
                throw new CborException('CBOR 整數超出 PHP 整數範圍');
            }

            $value = ($value << 8) | ord($byte);
        }

        return $value;
    }

    /** major type 1：負整數，編碼的是 -1 - n。 */
    private function readNegative(int $additionalInfo): int
    {
        $magnitude = $this->readUnsigned($additionalInfo);

        if ($magnitude === PHP_INT_MAX) {
            throw new CborException('CBOR 負整數超出 PHP 整數範圍');
        }

        return -1 - $magnitude;
    }

    /** 讀長度欄位：必須是非負且能放進 PHP int。 */
    private function readLength(int $additionalInfo): int
    {
        if ($additionalInfo === 31) {
            throw new CborException('不接受 indefinite-length（長度必須明確）');
        }

        return $this->readUnsigned($additionalInfo);
    }

    /** @return list<mixed> */
    private function readArray(int $additionalInfo, int $depth): array
    {
        $count = $this->readLength($additionalInfo);
        $this->assertRemaining($count);

        $items = [];

        for ($i = 0; $i < $count; $i++) {
            $items[] = $this->readValue($depth + 1);
        }

        return $items;
    }

    /** @return array<int|string, mixed> */
    private function readMap(int $additionalInfo, int $depth): array
    {
        $count = $this->readLength($additionalInfo);

        // 每個 entry 至少要 2 bytes（key + value），先擋掉「宣告一百萬個
        // entry 但只有 3 bytes 輸入」這種讓我們白跑迴圈的輸入。
        // 寫成除法而非 $count * 2，因為 $count 可能大到讓乘法溢位成負數。
        if ($count > intdiv(strlen($this->data) - $this->offset, 2)) {
            throw new CborException("CBOR map 宣告了 {$count} 個 entry，但資料長度不可能裝得下");
        }

        $map = [];

        for ($i = 0; $i < $count; $i++) {
            $key = $this->readValue($depth + 1);

            if (!is_int($key) && !is_string($key)) {
                throw new CborException('CBOR map 的 key 必須是整數或字串');
            }

            if (array_key_exists($key, $map)) {
                // 重複的 key 在規範裡是 ill-formed。不要讓「後蓋前」或
                // 「前蓋後」的差異變成驗證結果的差異。
                throw new CborException('CBOR map 有重複的 key');
            }

            $map[$key] = $this->readValue($depth + 1);
        }

        return $map;
    }

    private function take(int $length): string
    {
        if ($length < 0) {
            throw new CborException('CBOR 長度為負數');
        }

        $this->assertRemaining($length);

        $slice = substr($this->data, $this->offset, $length);
        $this->offset += $length;

        return $slice;
    }

    private function assertRemaining(int $needed): void
    {
        if ($needed > strlen($this->data) - $this->offset) {
            throw new CborException(sprintf(
                'CBOR 資料不足：需要 %d bytes，只剩 %d',
                $needed,
                strlen($this->data) - $this->offset,
            ));
        }
    }
}
