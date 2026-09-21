<?php

declare(strict_types=1);

namespace AppAttest\Store;

/** 一台註冊過的裝置。 */
final class Device
{
    public function __construct(
        public readonly string $id,
        public readonly string $platform,
        /** 註冊時從 attestation 抽出來的公鑰 */
        public readonly string $publicKeyPem,
        /** 目前記錄到的 signCount */
        public readonly int $counter,
    ) {
    }
}
