<?php

declare(strict_types=1);

namespace AppAttest\Http;

/**
 * 極簡路由。
 *
 * **這個檔案不是要你們照抄的部分** —— 你們有 Laravel / Symfony / Slim，
 * 用自己的路由和 middleware。它存在只是為了讓這個 repo 能獨立跑起來
 * 示範完整流程。
 *
 * 值得看的是 dispatch() 裡「受保護端點先過 guard」那個結構。
 */
final class Router
{
    public function __construct(
        private readonly AttestationController $attestation,
        private readonly ProtectedController $protected,
        private readonly AttestationGuard $guard,
    ) {
    }

    public function dispatch(Request $request, ?int $now = null): Response
    {
        $now ??= time();
        $route = $request->method . ' ' . $request->path;

        return match ($route) {
            'POST /attestation/challenge' => $this->attestation->challenge($request, $now),
            'POST /attestation/register' => $this->attestation->register($request, $now),

            // 受保護端點：先驗證，通過才進業務邏輯。
            // 在你們的框架裡這會是一個 middleware。
            'POST /protected/echo' => $this->guarded($request, $now),

            default => Response::notFound(),
        };
    }

    private function guarded(Request $request, int $now): Response
    {
        $result = $this->guard->verify($request, $now);

        // 業務邏輯只看這一個布林值。
        if (!$result->trusted) {
            return Response::rejected();
        }

        return $this->protected->echo($request, (string) $result->deviceId);
    }
}
