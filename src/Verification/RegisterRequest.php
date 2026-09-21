<?php

declare(strict_types=1);

namespace AppAttest\Verification;

/**
 * 註冊請求，已經解過 base64。
 *
 * 驗證核心只處理原始位元組 —— base64 解碼屬於 HTTP 層的責任。這樣驗證
 * 邏輯就不必關心編碼格式，也比較容易搬到別的傳輸層（gRPC、MQ）上。
 */
final class RegisterRequest
{
    public function __construct(
        public readonly string $platform,
        public readonly string $challengeId,
        /** 32 bytes raw */
        public readonly string $keyId,
        /** attestKey() 的原始輸出 */
        public readonly string $attestation,
    ) {
    }
}
