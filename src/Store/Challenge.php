<?php

declare(strict_types=1);

namespace AppAttest\Store;

/** 一個已發出的 challenge。 */
final class Challenge
{
    public function __construct(
        public readonly string $id,
        public readonly string $platform,
        /** 原始 32 bytes，不是 base64 */
        public readonly string $value,
        public readonly int $expiresAt,
    ) {
    }
}
