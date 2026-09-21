<?php

declare(strict_types=1);

namespace AppAttest\Http;

use AppAttest\Base64Url;
use AppAttest\Verification\RequestContext;
use AppAttest\Verification\VerifierRegistry;
use AppAttest\Verification\VerifyResult;

/**
 * 把 HTTP header 轉成 RequestContext，交給驗證層。
 *
 * 這是「受保護端點」與「驗證層」之間唯一的接縫。業務邏輯只需要：
 *
 *     $result = $guard->verify($request, time());
 *     if (!$result->trusted) { return Response::rejected(); }
 *
 * 不需要知道 iOS 還是 Android、不需要知道什麼是 assertion。
 */
final class AttestationGuard
{
    public const HEADER_PLATFORM = 'X-Attest-Platform';
    public const HEADER_DEVICE_ID = 'X-Attest-Device-Id';
    public const HEADER_CHALLENGE_ID = 'X-Attest-Challenge-Id';
    public const HEADER_REQUEST_HASH = 'X-Attest-Request-Hash';
    public const HEADER_ASSERTION = 'X-Attest-Assertion';
    public const HEADER_INTEGRITY_TOKEN = 'X-Attest-Integrity-Token';

    public function __construct(
        private readonly VerifierRegistry $registry,
        private readonly Logger $logger,
    ) {
    }

    public function verify(Request $request, int $now): VerifyResult
    {
        $platform = $request->header(self::HEADER_PLATFORM);

        // 平台專屬的憑證欄位。iOS 是 assertion（標準 base64），
        // Android 之後會是 Play Integrity token。
        $proof = match ($platform) {
            'ios' => Base64Url::decodeStandard($request->header(self::HEADER_ASSERTION)) ?? '',
            default => $request->header(self::HEADER_INTEGRITY_TOKEN),
        };

        $context = new RequestContext(
            platform: $platform,
            deviceId: $request->header(self::HEADER_DEVICE_ID),
            challengeId: $request->header(self::HEADER_CHALLENGE_ID),
            requestHashFromClient: $request->header(self::HEADER_REQUEST_HASH),
            proof: $proof,
            // 注意傳的是原始請求，不是算好的 hash。驗證器自己重算。
            method: $request->method,
            path: $request->path,
            body: $request->body,
        );

        $result = $this->registry->verifyRequest($context, $now);

        if (!$result->trusted) {
            $this->logger->warning('request rejected', [
                'platform' => $platform,
                'deviceId' => $context->deviceId,
                'path' => $request->path,
                'reasons' => $result->reasonsAsString(),
            ]);
        }

        return $result;
    }
}
