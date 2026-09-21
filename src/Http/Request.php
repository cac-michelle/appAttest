<?php

declare(strict_types=1);

namespace AppAttest\Http;

/**
 * 一個 HTTP 請求。
 *
 * 刻意不直接讀 $_SERVER / php://input：把 superglobal 的讀取留在
 * public/index.php，其餘程式碼都能在測試裡直接建構請求。
 */
final class Request
{
    /** @param array<string, string> $headers key 一律小寫 */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $headers,
        public readonly string $body,
    ) {
    }

    public function header(string $name): string
    {
        return $this->headers[strtolower($name)] ?? '';
    }

    /** 解析 JSON body，失敗回 null。 */
    public function json(): ?array
    {
        if ($this->body === '') {
            return null;
        }

        $decoded = json_decode($this->body, true);

        return is_array($decoded) ? $decoded : null;
    }

    /** 從 PHP 的 superglobal 建立請求。只有 public/index.php 該呼叫這個。 */
    public static function fromGlobals(): self
    {
        $headers = [];

        foreach ($_SERVER as $key => $value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                // HTTP_X_ATTEST_DEVICE_ID → x-attest-device-id
                $name = strtolower(str_replace('_', '-', substr((string) $key, 5)));
                $headers[$name] = (string) $value;
            }
        }

        // path 必須去掉 query string —— requestHash 算的是不含 query 的
        // path，這裡漏掉會讓帶 query 的請求全部驗不過。
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = (string) (parse_url($uri, PHP_URL_PATH) ?: '/');

        return new self(
            method: strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')),
            path: $path,
            headers: $headers,
            body: (string) file_get_contents('php://input'),
        );
    }
}
