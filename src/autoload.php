<?php

declare(strict_types=1);

/**
 * 最小 PSR-4 autoloader。
 *
 * 這個 repo 刻意沒有 runtime 相依套件，所以不需要 composer 就能跑：
 *   require __DIR__ . '/src/autoload.php';
 *
 * 你們專案裡已經有 composer autoload 的話，直接把 src/ 掛到自己的
 * PSR-4 設定下即可，這個檔案不用搬。
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'AppAttest\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require $path;
    }
});
