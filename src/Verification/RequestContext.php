<?php

declare(strict_types=1);

namespace AppAttest\Verification;

/**
 * 一個受保護請求的全部驗證材料。
 *
 * === 注意這裡帶的是 method / path / body，不是算好的 hash ===
 *
 * 驗證器拿到的是**原始請求**，requestHash 由它自己重算。這不是多此一舉：
 * 如果這個物件只帶一個「requestHash」欄位，那麼某天某個人在某個
 * controller 裡直接把 header 的值塞進來，驗證就完全失效了，而且看起來
 * 一切正常。
 *
 * 讓型別本身就不允許「信任 client 的 hash」，比寫註解提醒有效得多。
 */
final class RequestContext
{
    public function __construct(
        public readonly string $platform,
        public readonly string $deviceId,
        public readonly string $challengeId,
        /** client 在 header 宣告的 requestHash，只拿來比對 */
        public readonly string $requestHashFromClient,
        /** 平台專屬的憑證：iOS 是 assertion 的原始位元組 */
        public readonly string $proof,
        public readonly string $method,
        public readonly string $path,
        public readonly string $body,
    ) {
    }
}
