<?php

declare(strict_types=1);

namespace AppAttest\Http;

final class Response
{
    /** @param array<string, mixed> $payload */
    public function __construct(
        public readonly int $status,
        public readonly array $payload,
    ) {
    }

    /** @param array<string, mixed> $payload */
    public static function ok(array $payload): self
    {
        return new self(200, $payload);
    }

    public static function badRequest(string $error): self
    {
        return new self(400, ['error' => $error]);
    }

    /**
     * 驗證失敗的統一回應。
     *
     * **不帶任何原因。** 具體是哪一關沒過只寫進 server log —— 見
     * Verification\Reason 的說明。
     */
    public static function rejected(): self
    {
        return new self(401, ['deviceId' => null, 'status' => 'rejected']);
    }

    public static function notFound(): self
    {
        return new self(404, ['error' => 'not_found']);
    }

    public function send(): void
    {
        http_response_code($this->status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($this->payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
