<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Store\ChallengeStore;
use AppAttest\Store\DeviceStore;
use AppAttest\Verification\AttestationVerifier;
use AppAttest\Verification\Reason;
use AppAttest\Verification\RegisterRequest;
use AppAttest\Verification\RequestContext;
use AppAttest\Verification\VerificationFailure;
use AppAttest\Verification\VerifyResult;

/**
 * iOS App Attest 驗證器。
 *
 * 這個類別負責把「流程」和「密碼學檢查」接起來：
 *   - 流程（消耗 challenge、查裝置、寫回 counter）在這裡
 *   - 密碼學檢查在 AttestationValidator / AssertionValidator 裡
 *
 * 分開的好處是那兩個 Validator 完全不碰資料庫，可以用純位元組單測。
 *
 * 這裡是例外轉回傳值的邊界：內部的 VerificationFailure 到此為止，
 * 對外只吐 VerifyResult。
 */
final class IosVerifier implements AttestationVerifier
{
    public const PLATFORM = 'ios';

    public function __construct(
        private readonly AttestationValidator $attestationValidator,
        private readonly AssertionValidator $assertionValidator,
        private readonly ChallengeStore $challenges,
        private readonly DeviceStore $devices,
    ) {
    }

    public function platform(): string
    {
        return self::PLATFORM;
    }

    public function verifyRegistration(RegisterRequest $request, int $now): VerifyResult
    {
        try {
            // 先消耗 challenge。即使後面驗證失敗，這個 challenge 也已經
            // 作廢了 —— 這是刻意的：讓攻擊者沒辦法拿同一個 challenge
            // 反覆嘗試不同的 attestation。每試一次就得重新跟 server 要。
            $challenge = $this->challenges->consume($request->challengeId, $now);

            if ($challenge === null) {
                throw VerificationFailure::of(Reason::CHALLENGE_NOT_FOUND);
            }

            $validated = $this->attestationValidator->validate(
                attestationBytes: $request->attestation,
                keyIdFromClient: $request->keyId,
                challenge: $challenge->value,
                now: $now,
            );

            $deviceId = $this->devices->create(self::PLATFORM, $validated->publicKeyPem, $now);

            return VerifyResult::trusted(self::PLATFORM, $deviceId);
        } catch (VerificationFailure $failure) {
            return VerifyResult::rejected(self::PLATFORM, $failure->reason);
        }
    }

    public function verifyRequest(RequestContext $context, int $now): VerifyResult
    {
        try {
            $challenge = $this->challenges->consume($context->challengeId, $now);

            if ($challenge === null) {
                throw VerificationFailure::of(Reason::CHALLENGE_NOT_FOUND);
            }

            $device = $this->devices->get($context->deviceId);

            if ($device === null) {
                throw VerificationFailure::of(Reason::DEVICE_NOT_FOUND);
            }

            // server 依實際收到的 method / path / body 重算 requestHash，
            // 再跟 header 比對。header 的值從不被當成事實。
            $requestHash = AssertionValidator::requireMatchingRequestHash(
                requestHashFromClient: $context->requestHashFromClient,
                method: $context->method,
                path: $context->path,
                body: $context->body,
                challenge: $challenge->value,
            );

            $newCounter = $this->assertionValidator->validate(
                assertionBytes: $context->proof,
                publicKeyPem: $device->publicKeyPem,
                storedCounter: $device->counter,
                requestHash: $requestHash,
            );

            // 條件式更新。回傳 false 表示有另一個併發請求搶先用掉了這個
            // counter 值 —— 正常流程不會發生（challenge 已經是一次性的），
            // 發生就代表有人在重放，拒絕。
            if (!$this->devices->updateCounter($context->deviceId, $newCounter)) {
                throw VerificationFailure::of(
                    Reason::COUNTER_NOT_INCREASING,
                    'counter 條件式更新失敗，可能有併發重放',
                );
            }

            return VerifyResult::trusted(self::PLATFORM, $context->deviceId);
        } catch (VerificationFailure $failure) {
            return VerifyResult::rejected(self::PLATFORM, $failure->reason, $context->deviceId);
        }
    }
}
