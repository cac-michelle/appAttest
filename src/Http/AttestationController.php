<?php

declare(strict_types=1);

namespace AppAttest\Http;

use AppAttest\Base64Url;
use AppAttest\Store\ChallengeStore;
use AppAttest\Verification\RegisterRequest;
use AppAttest\Verification\VerifierRegistry;

/**
 * /attestation/challenge 與 /attestation/register。
 */
final class AttestationController
{
    public function __construct(
        private readonly ChallengeStore $challenges,
        private readonly VerifierRegistry $registry,
        private readonly Logger $logger,
    ) {
    }

    /** POST /attestation/challenge */
    public function challenge(Request $request, int $now): Response
    {
        $body = $request->json();
        $platform = $body['platform'] ?? null;

        if (!is_string($platform)) {
            return Response::badRequest('platform_required');
        }

        // platform 只拿來路由。即使這裡通過，真正的平台證明仍然來自
        // attestation 裡的 App ID。
        if (!$this->registry->supports($platform)) {
            return Response::badRequest('unsupported_platform');
        }

        $challenge = $this->challenges->issue($platform, $now);

        return Response::ok([
            'challenge' => Base64Url::encode($challenge->value),
            'challengeId' => $challenge->id,
            'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', $challenge->expiresAt),
        ]);
    }

    /** POST /attestation/register */
    public function register(Request $request, int $now): Response
    {
        $body = $request->json();

        if ($body === null) {
            return Response::badRequest('invalid_json');
        }

        $platform = $body['platform'] ?? null;
        $challengeId = $body['challengeId'] ?? null;
        $keyIdB64 = $body['keyId'] ?? null;
        $attestationB64 = $body['attestation'] ?? null;

        if (!is_string($platform) || !is_string($challengeId)
            || !is_string($keyIdB64) || !is_string($attestationB64)) {
            return Response::badRequest('missing_fields');
        }

        // iOS 的 App Attest API 給的是標準 base64（不是 base64url）。
        $keyId = Base64Url::decodeStandard($keyIdB64);
        $attestation = Base64Url::decodeStandard($attestationB64);

        if ($keyId === null || $attestation === null) {
            return Response::badRequest('invalid_base64');
        }

        $result = $this->registry->verifyRegistration(
            new RegisterRequest($platform, $challengeId, $keyId, $attestation),
            $now,
        );

        if (!$result->trusted) {
            // 原因只留在 log。回給 client 的永遠是同一個 401。
            $this->logger->warning('register rejected', [
                'platform' => $platform,
                'challengeId' => $challengeId,
                'reasons' => $result->reasonsAsString(),
            ]);

            return Response::rejected();
        }

        $this->logger->info('device registered', [
            'platform' => $result->platform,
            'deviceId' => (string) $result->deviceId,
        ]);

        return Response::ok([
            'deviceId' => $result->deviceId,
            'status' => 'trusted',
        ]);
    }
}
