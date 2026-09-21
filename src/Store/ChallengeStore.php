<?php

declare(strict_types=1);

namespace AppAttest\Store;

interface ChallengeStore
{
    /** 產生並儲存一個新的一次性 challenge。 */
    public function issue(string $platform, int $now): Challenge;

    /**
     * 消耗一個 challenge。
     *
     * ┌────────────────────────────────────────────────────────────────┐
     * │ 這**必須**是單一原子操作，不可以寫成「先查、再標記」兩步。      │
     * └────────────────────────────────────────────────────────────────┘
     *
     * 寫成兩步的話，兩個併發的請求會同時查到同一個「未使用」的
     * challenge，兩個都通過檢查，然後各自標記一次。攻擊者只要把攔截到的
     * 請求同時重送幾份，就能突破一次性限制 —— replay 防護直接失效，而且
     * 單執行緒測試永遠測不出來。
     *
     * 回傳 null 涵蓋三種情況：不存在、已過期、已被使用。**對呼叫端來說
     * 這三者沒有差別**，都是「這個 challenge 不能用」。
     */
    public function consume(string $challengeId, int $now): ?Challenge;

    /** 清掉過期的資料，回傳刪除筆數。給排程工作用。 */
    public function purgeExpired(int $now): int;
}
