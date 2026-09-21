<?php

declare(strict_types=1);

namespace AppAttest\Http;

/**
 * 極簡 logger，寫到 stderr。
 *
 * 存在的意義只是讓「失敗原因寫 log、不回給 client」這件事有個具體去處。
 * 你們專案裡有 PSR-3 logger 的話，把這個類別換成注入 LoggerInterface 即可。
 *
 * 測試時傳 silent() 進去，免得測試輸出被大量預期中的拒絕訊息淹沒。
 */
class Logger
{
    public function __construct(private readonly bool $enabled = true)
    {
    }

    public static function silent(): self
    {
        return new self(false);
    }

    /** @param array<string, mixed> $context */
    public function info(string $message, array $context = []): void
    {
        $this->write('INFO', $message, $context);
    }

    /** @param array<string, mixed> $context */
    public function warning(string $message, array $context = []): void
    {
        $this->write('WARN', $message, $context);
    }

    /** @param array<string, mixed> $context */
    private function write(string $level, string $message, array $context): void
    {
        if (!$this->enabled) {
            return;
        }

        $parts = [];

        foreach ($context as $key => $value) {
            $parts[] = $key . '=' . (is_scalar($value) ? (string) $value : json_encode($value));
        }

        // 用 error_log() 而不是 fwrite(STDERR, …)。
        //
        // STDERR 這個常數只有 CLI SAPI 會定義；在 php-fpm / mod_php /
        // 內建 server 底下它不存在，寫下去會 fatal error。
        //
        // 而 logger 只在**驗證失敗時**被呼叫 —— 所以這種寫法會讓本該回
        // 401 的請求變成 500（或更糟，變成帶 HTML 錯誤訊息的 200）。
        // CLI 跑的測試永遠抓不到，因為 CLI 有 STDERR。
        //
        // error_log() 在所有 SAPI 都能用，會送到該環境的錯誤日誌。
        error_log(sprintf('[app-attest] %s %s %s', $level, $message, implode(' ', $parts)));
    }
}
