<?php

declare(strict_types=1);

/**
 * demo HTTP 入口。
 *
 *     APP_ID=ABCDE12345.com.example.app \
 *     APPLE_ROOT_CA_PEM=certs/apple-app-attest-root-ca.pem \
 *     php -S 127.0.0.1:8080 -t public
 *
 * **這個檔案不是要你們照抄的部分。** 你們有自己的框架、自己的
 * middleware、自己的 DI container。要搬走的是 src/Verification/ 和
 * src/Store/ 的介面。
 */

require __DIR__ . '/../vendor/autoload.php';

use AppAttest\App;
use AppAttest\Config;
use AppAttest\Http\Request;
use AppAttest\Http\Response;

try {
    $config = Config::fromEnvironment();
} catch (Throwable $e) {
    // 設定錯誤要大聲失敗，不要讓服務帶著錯的 App ID 安靜地跑起來 ——
    // 那會變成「所有驗證都失敗」而且極難查。
    (new Response(500, ['error' => 'configuration_error', 'detail' => $e->getMessage()]))->send();
    exit(1);
}

App::create($config)->router->dispatch(Request::fromGlobals())->send();
