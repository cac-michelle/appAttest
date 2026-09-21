<?php

declare(strict_types=1);

namespace AppAttest\Verification;

/**
 * 依 platform 把請求路由到對應的驗證器。
 *
 * === platform 欄位不可信任 ===
 *
 * 它只用來決定「用哪一套驗證邏輯」，本身不構成任何信任基礎。真正的
 * 平台證明來自驗證內容：
 *   - iOS：attestation 裡的 App ID（rpIdHash）
 *   - Android：Play Integrity token 裡的 package name
 *
 * 攻擊者把 platform 改成 "android" 也沒用 —— 那只會讓請求落到 Android
 * 驗證器，而他沒有合法的 Play Integrity token。目前更簡單：沒有註冊
 * Android 驗證器，直接被擋在這裡。
 */
final class VerifierRegistry
{
    /** @var array<string, AttestationVerifier> */
    private array $verifiers = [];

    /** @param list<AttestationVerifier> $verifiers */
    public function __construct(array $verifiers)
    {
        foreach ($verifiers as $verifier) {
            $this->verifiers[$verifier->platform()] = $verifier;
        }
    }

    public function supports(string $platform): bool
    {
        return isset($this->verifiers[$platform]);
    }

    public function verifyRegistration(RegisterRequest $request, int $now): VerifyResult
    {
        $verifier = $this->verifiers[$request->platform] ?? null;

        if ($verifier === null) {
            return VerifyResult::rejected($request->platform, Reason::UNSUPPORTED_PLATFORM);
        }

        return $verifier->verifyRegistration($request, $now);
    }

    public function verifyRequest(RequestContext $context, int $now): VerifyResult
    {
        $verifier = $this->verifiers[$context->platform] ?? null;

        if ($verifier === null) {
            return VerifyResult::rejected($context->platform, Reason::UNSUPPORTED_PLATFORM, $context->deviceId);
        }

        return $verifier->verifyRequest($context, $now);
    }
}
