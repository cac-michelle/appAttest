<?php

declare(strict_types=1);

/**
 * 產生 requestHash 的跨語言測試向量。
 *
 *     php tools/generate-request-hash-vectors.php
 *
 * 輸出到 ios/Tests/AppAttestClientTests/Fixtures/request-hash-vectors.json，
 * 由 PHP 與 Swift 兩邊的測試共同驗證。
 *
 * PHP 是 requestHash 合約的權威來源，所以向量由這一側產生。
 *
 * **只有在真的要改合約時才重新產生**，而且改完兩邊都要發版 —— 舊版
 * client 會全部驗不過。用固定的亂數種子，所以重跑結果一致。
 */
require __DIR__ . '/../src/autoload.php';

use AppAttest\RequestHash;

mt_srand(20260921);   // 固定種子，重跑結果一致

$methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
$paths = [
    '/protected/echo',
    '/',
    '/a/b/c/d/e',
    '/protected/%E4%B8%AD%E6%96%87',          // 百分號編碼的中文
    '/a%20b',                                  // 空白
    '/users/123/orders',
    '/%F0%9F%8E%89',                           // emoji
    '/protected/echo.json',
    '/v2/resource-with-dashes_and_underscores',
    '/%2Fescaped-slash',
];
$bodies = [
    '',
    '{}',
    '{"message":"hi"}',
    '{"amount":1000000,"currency":"TWD"}',
    '{"中文":"測試","emoji":"🎉"}',
    str_repeat('x', 4096),
    "\x00\x01\x02\xFF binary-ish",              // 含 null byte
    '[]',
];

$cases = [];
foreach ($paths as $path) {
    foreach ($bodies as $body) {
        $method = $methods[count($cases) % count($methods)];
        $challenge = '';
        for ($i = 0; $i < 32; $i++) { $challenge .= chr(mt_rand(0, 255)); }

        $cases[] = [
            'method' => $method,
            'path' => $path,
            'bodyBase64' => base64_encode($body),
            'challengeBase64' => base64_encode($challenge),
            'expected' => RequestHash::compute($method, $path, $body, $challenge),
        ];
    }
}

file_put_contents(
    __DIR__ . '/../ios/Tests/AppAttestClientTests/Fixtures/request-hash-vectors.json',
    json_encode($cases, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n"
);

echo "產生 " . count($cases) . " 組向量\n";
