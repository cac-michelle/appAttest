<?php

declare(strict_types=1);

namespace AppAttest;

use RuntimeException;

/**
 * 驗證所需的設定。
 *
 * 全部從環境變數讀，沒有預設的 APP_ID —— 少設定就直接爆，不要讓服務
 * 帶著錯的 App ID 安靜地跑起來（那樣所有驗證都會失敗，而且很難查）。
 */
final class Config
{
    public const ENV_DEVELOPMENT = 'development';
    public const ENV_PRODUCTION = 'production';

    /**
     * attestation 裡的 aaguid 欄位，用來區分 App 跑在哪個環境。
     *
     * 這兩個值都剛好是 16 bytes：
     *   development = "appattestdevelop"（16 個字元）
     *   production  = "appattest" + 7 個 \x00
     *
     * 為什麼要檢查：如果只認 development，有人用 TestFlight/開發版
     * App 產生的 attestation 也能通過正式環境的驗證，那就等於允許
     * 未上架、可被除錯器附加的 App 存取正式 API。
     */
    private const AAGUID_DEVELOPMENT = 'appattestdevelop';
    private const AAGUID_PRODUCTION = "appattest\x00\x00\x00\x00\x00\x00\x00";

    public function __construct(
        /** "<TeamID>.<BundleID>"，例如 "ABCDE12345.com.example.app" */
        public readonly string $appId,
        /** self::ENV_DEVELOPMENT 或 self::ENV_PRODUCTION */
        public readonly string $environment,
        /** 信任錨點的 PEM 內容（不是路徑）。 */
        public readonly string $rootCaPem,
        public readonly int $challengeTtlSeconds,
        public readonly string $sqlitePath,
    ) {
        if ($appId === '' || !str_contains($appId, '.')) {
            throw new RuntimeException('APP_ID 必須是 "<TeamID>.<BundleID>" 格式');
        }

        if (!in_array($environment, [self::ENV_DEVELOPMENT, self::ENV_PRODUCTION], true)) {
            throw new RuntimeException('ATTEST_ENVIRONMENT 只能是 development 或 production');
        }

        if ($challengeTtlSeconds < 1) {
            throw new RuntimeException('CHALLENGE_TTL_SECONDS 必須大於 0');
        }
    }

    public static function fromEnvironment(): self
    {
        $rootCaPath = self::env('APPLE_ROOT_CA_PEM', __DIR__ . '/../certs/apple-app-attest-root-ca.pem');
        $rootCaPem = @file_get_contents($rootCaPath);

        if ($rootCaPem === false) {
            throw new RuntimeException(
                "讀不到 root CA：{$rootCaPath}。" .
                '正式環境請放 Apple App Attest Root CA（見 certs/README.md），' .
                '跑測試時請指向測試夾具產生的自簽 CA。',
            );
        }

        return new self(
            appId: self::env('APP_ID', ''),
            environment: self::env('ATTEST_ENVIRONMENT', self::ENV_DEVELOPMENT),
            rootCaPem: $rootCaPem,
            challengeTtlSeconds: (int) self::env('CHALLENGE_TTL_SECONDS', '300'),
            sqlitePath: self::env('SQLITE_PATH', __DIR__ . '/../var/attest.sqlite'),
        );
    }

    /**
     * App ID 的 SHA-256。attestation 裡的 rpIdHash 必須等於這個值。
     *
     * 第三個參數 true 代表回傳 raw binary（32 bytes）而不是 64 字元的
     * hex 字串。這整份程式碼裡所有 hash 都是 raw binary，漏掉 true 會讓
     * 比對永遠失敗，而且錯誤訊息完全看不出原因。
     */
    public function appIdHash(): string
    {
        return hash('sha256', $this->appId, true);
    }

    /** 這個環境預期的 aaguid（16 bytes）。 */
    public function expectedAaguid(): string
    {
        return $this->environment === self::ENV_PRODUCTION
            ? self::AAGUID_PRODUCTION
            : self::AAGUID_DEVELOPMENT;
    }

    private static function env(string $key, string $default): string
    {
        $value = getenv($key);

        return $value === false || $value === '' ? $default : $value;
    }
}
