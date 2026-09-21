<?php

declare(strict_types=1);

namespace AppAttest\Store\Sqlite;

/**
 * 產生 UUID v4。
 *
 * 用 random_bytes()（密碼學安全）而不是 uniqid() 或 mt_rand()。
 * deviceId 和 challengeId 都不該是可預測的。
 */
final class Uuid
{
    public static function v4(): string
    {
        $bytes = random_bytes(16);

        // 設定 version（4）與 variant（RFC 4122）欄位。
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
