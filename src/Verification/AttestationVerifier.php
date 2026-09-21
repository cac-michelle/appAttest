<?php

declare(strict_types=1);

namespace AppAttest\Verification;

/**
 * 統一的驗證介面。
 *
 * === 這層抽象的價值 ===
 *
 * 上層業務邏輯永遠不用分「iOS 還是 Android」。它只問一件事：
 *
 *     if (!$result->trusted) { return 401; }
 *
 * 日後要加 Android，做的事情是「新增一個實作這個介面的類別，註冊進
 * VerifierRegistry」。API 合約、header 結構、業務邏輯全部不動。
 *
 * 目前只有 IosVerifier 一個實作。介面看起來像是多餘的一層，但它把
 * 「平台差異止於此處」這件事寫進了型別系統裡 —— 之後不會有人為了趕
 * 進度，把 Play Integrity 的判斷直接寫進 controller。
 */
interface AttestationVerifier
{
    /** 這個驗證器負責的平台代碼，例如 "ios"。 */
    public function platform(): string;

    /**
     * 驗證一次性的裝置註冊。
     *
     * 成功時回傳的 VerifyResult 會帶上新發的 deviceId。
     * **不丟例外** —— 驗證失敗是預期中的正常結果。
     */
    public function verifyRegistration(RegisterRequest $request, int $now): VerifyResult;

    /**
     * 驗證一個受保護請求。
     *
     * **不丟例外** —— 驗證失敗是預期中的正常結果。
     */
    public function verifyRequest(RequestContext $context, int $now): VerifyResult;
}
