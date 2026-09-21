<?php

declare(strict_types=1);

namespace AppAttest;

/**
 * base64url 編解碼（RFC 4648 §5），無 padding。
 *
 * 跟一般 base64 的差別只有兩個字元：+ → -、/ → _，並去掉結尾的 =。
 * 這樣值可以安全地放進 URL 和 HTTP header 而不需要額外轉義。
 */
final class Base64Url
{
    public static function encode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * 解碼。輸入不是合法 base64url 時回傳 null，**不要**回傳空字串 ——
     * 呼叫端必須能區分「解出空資料」和「輸入根本是垃圾」。
     */
    public static function decode(string $encoded): ?string
    {
        if ($encoded !== '' && preg_match('/^[A-Za-z0-9\-_]+$/', $encoded) !== 1) {
            return null;
        }

        // strict 模式：遇到非法字元回 false 而不是靜默略過。
        $decoded = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    /**
     * 解標準 base64（client 送 keyId 和 attestation 用的格式）。
     *
     * App Attest 的 iOS API 給的是標準 base64，不是 base64url，所以
     * register 端點收到的欄位要用這個解。
     */
    public static function decodeStandard(string $encoded): ?string
    {
        $decoded = base64_decode($encoded, true);

        return $decoded === false ? null : $decoded;
    }
}
