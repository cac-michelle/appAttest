<?php

declare(strict_types=1);

namespace AppAttest\Http;

/**
 * 示範用的受保護端點。
 *
 * 重點在它有多無聊：驗證全部發生在這之前，業務邏輯完全不知道
 * App Attest 的存在，只收到一個已經可信的 deviceId。
 */
final class ProtectedController
{
    public function echo(Request $request, string $deviceId): Response
    {
        return Response::ok([
            'deviceId' => $deviceId,
            'echo' => $request->json() ?? [],
        ]);
    }
}
