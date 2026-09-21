<?php

declare(strict_types=1);

namespace AppAttest\Store;

interface DeviceStore
{
    /** 建立一台新裝置，counter 初始為 0，回傳 deviceId。 */
    public function create(string $platform, string $publicKeyPem, int $now): string;

    public function get(string $deviceId): ?Device;

    /**
     * 更新 counter。
     *
     * 實作必須是條件式更新（只在新值大於舊值時才寫入），回傳是否真的
     * 更新成功。理由跟 ChallengeStore::consume() 一樣：兩個併發請求帶
     * 同一個 counter 值時，條件式更新能讓其中一個失敗。
     *
     * challenge 的一次性已經擋掉大部分重放，這是第二道防線 —— 安全機制
     * 不該只靠單一環節。
     */
    public function updateCounter(string $deviceId, int $newCounter): bool;
}
