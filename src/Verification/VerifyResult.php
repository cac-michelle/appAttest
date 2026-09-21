<?php

declare(strict_types=1);

namespace AppAttest\Verification;

/**
 * 正規化後的驗證結果 —— 這是驗證層對外唯一的輸出型別。
 *
 * 業務邏輯只該讀 $trusted。平台差異（iOS 的 assertion 簽章、Android 的
 * Play Integrity token）全部在驗證器內部消化掉，不往上洩漏。
 *
 * 這個設計的價值在日後加 Android 時才看得出來：新增一個驗證器、註冊進
 * VerifierRegistry，上層一行都不用改。
 */
final class VerifyResult
{
    /** @param list<Reason> $reasons */
    private function __construct(
        public readonly bool $trusted,
        public readonly string $platform,
        public readonly ?string $deviceId,
        public readonly array $reasons,
    ) {
    }

    public static function trusted(string $platform, string $deviceId): self
    {
        return new self(true, $platform, $deviceId, []);
    }

    /**
     * 驗證失敗。
     *
     * $deviceId 即使失敗也帶上（如果知道的話）—— 方便在 log 裡追是哪台
     * 裝置一直被拒，但**不會**出現在 HTTP 回應裡。
     */
    public static function rejected(string $platform, Reason $reason, ?string $deviceId = null): self
    {
        return new self(false, $platform, $deviceId, [$reason]);
    }

    /** log 用的單行字串。 */
    public function reasonsAsString(): string
    {
        return implode(',', array_map(static fn (Reason $r): string => $r->value, $this->reasons));
    }
}
