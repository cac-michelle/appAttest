<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

/** attestation 全數檢查通過後，我們要留下來的東西。 */
final class ValidatedAttestation
{
    public function __construct(
        /** 之後驗 assertion 要用的公鑰 */
        public readonly string $publicKeyPem,
        /** keyId，32 bytes raw */
        public readonly string $keyId,
    ) {
    }
}
