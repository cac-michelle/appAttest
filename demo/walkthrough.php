<?php

declare(strict_types=1);

/**
 * 逐步走過一次完整的 App Attest 流程，把每一步算的東西印出來。
 *
 *     php demo/walkthrough.php
 *
 * 這是給人看的 —— 在讀 src/ 之前先跑一次，對整個流程會有具體的感覺。
 * 用的是假的 Apple CA 和假裝置，但驗證程式碼跟正式環境完全相同。
 */

require __DIR__ . '/../vendor/autoload.php';

use AppAttest\App;
use AppAttest\Base64Url;
use AppAttest\Cbor\CborDecoder;
use AppAttest\Config;
use AppAttest\Http\AttestationGuard;
use AppAttest\Http\Logger;
use AppAttest\Http\Request;
use AppAttest\Http\Response;
use AppAttest\RequestHash;
use AppAttest\Tests\Fixture\FakeAppleCa;
use AppAttest\Tests\Fixture\FakeDevice;
use AppAttest\Tests\Fixture\Flaw;
use AppAttest\Verification\Ios\NonceExtension;

const APP_ID = 'ABCDE12345.com.example.app';

// ---------------------------------------------------------------------
// 輸出小工具
// ---------------------------------------------------------------------

function step(string $title): void
{
    echo "\n\033[1;36m" . str_repeat('─', 72) . "\033[0m\n";
    echo "\033[1;36m{$title}\033[0m\n";
    echo "\033[1;36m" . str_repeat('─', 72) . "\033[0m\n";
}

/**
 * 補齊到指定的顯示寬度。
 *
 * 不能用 printf 的 %-26s：那個數的是位元組，中文字一個佔 3 bytes 卻只
 * 顯示 2 格寬，欄位會歪掉。mb_strwidth() 數的才是終端機上的顯示寬度。
 */
function pad(string $text, int $width): string
{
    return $text . str_repeat(' ', max(1, $width - mb_strwidth($text, 'UTF-8')));
}

function line(string $label, string $value): void
{
    echo '    ' . pad($label, 26) . ' ' . $value . "\n";
}

function check(string $label, string $detail = ''): void
{
    echo "    \033[32m✓\033[0m " . pad($label, 24) . ' ' . $detail . "\n";
}

function blocked(string $attack, Response $response, string $why): void
{
    $status = $response->status === 401
        ? "\033[32m擋下 (401)\033[0m"
        : "\033[31m沒擋住 ({$response->status})\033[0m";

    echo '    ' . pad($attack, 34) . ' ' . $status . "\n";
    echo '    ' . str_repeat(' ', 34) . "   ↳ \033[2m{$why}\033[0m\n";
}

/** 長的位元組串只印頭尾，中間省略。 */
function hex(string $bytes, int $keep = 8): string
{
    $h = bin2hex($bytes);

    if (strlen($h) <= $keep * 4) {
        return $h;
    }

    return substr($h, 0, $keep * 2) . '…' . substr($h, -$keep * 2) . ' (' . strlen($bytes) . ' bytes)';
}

// ---------------------------------------------------------------------
// 組裝
// ---------------------------------------------------------------------

$config = new Config(
    appId: APP_ID,
    environment: Config::ENV_DEVELOPMENT,
    // 正式環境這裡是 Apple App Attest Root CA。
    rootCaPem: FakeAppleCa::shared()->rootPem,
    challengeTtlSeconds: 300,
    sqlitePath: ':memory:',
);

$app = App::create($config, Logger::silent());
$device = new FakeDevice(APP_ID);

echo "\n\033[1mApp Attest 後端驗證 — 逐步演示\033[0m\n";
line('App ID', APP_ID);
line('環境', $config->environment);
line('信任錨點', '假的 Apple Root CA（正式環境換成 Apple 官方憑證）');
line('App ID hash', hex($config->appIdHash()));

// ---------------------------------------------------------------------
// 1. 要 challenge
// ---------------------------------------------------------------------

step('[1] 裝置向後端要一個 challenge');

$response = $app->router->dispatch(new Request(
    'POST',
    '/attestation/challenge',
    [],
    (string) json_encode(['platform' => 'ios']),
));

$challengeId = (string) $response->payload['challengeId'];
$challenge = (string) Base64Url::decode((string) $response->payload['challenge']);

line('challengeId', $challengeId);
line('challenge (base64url)', (string) $response->payload['challenge']);
line('challenge (hex)', hex($challenge));
line('expiresAt', (string) $response->payload['expiresAt']);
echo "\n    challenge 是 32 bytes 的密碼學亂數、一次性、5 分鐘後過期。\n";
echo "    後端記住它；裝置不能自己造一個。\n";

// ---------------------------------------------------------------------
// 2. 裝置產生 attestation
// ---------------------------------------------------------------------

step('[2] 裝置在 Secure Enclave 產生金鑰並取得 attestation');

$attestation = $device->attest($challenge);
$decoded = CborDecoder::decode($attestation);
$authData = $decoded['authData'];

line('keyId', hex($device->keyId()));
line('attestation 總長', strlen($attestation) . ' bytes (CBOR)');
line('  fmt', $decoded['fmt']);
line('  x5c', count($decoded['attStmt']['x5c']) . ' 張憑證：credCert + intermediate');
line('  authData', strlen($authData) . ' bytes');
echo "\n    authData 的位元組佈局：\n";
line('    rpIdHash (0-31)', hex(substr($authData, 0, 32)));
line('    flags (32)', sprintf('0x%02X', ord($authData[32])));
line('    signCount (33-36)', (string) unpack('N', substr($authData, 33, 4))[1] . '  ← 註冊時必為 0');
line('    aaguid (37-52)', '"' . substr($authData, 37, 16) . '"  ← 環境識別');
line('    credentialId (55-86)', hex(substr($authData, 55, 32)) . '  ← 就是 keyId');
line('    COSE 公鑰 (87-)', strlen($authData) - 87 . ' bytes');

// ---------------------------------------------------------------------
// 3. 後端驗證
// ---------------------------------------------------------------------

step('[3] 後端驗證 attestation —— Apple 規範的七項檢查');

$clientDataHash = hash('sha256', $challenge, true);
$expectedNonce = hash('sha256', $authData . $clientDataHash, true);

$credCertPem = "-----BEGIN CERTIFICATE-----\n"
    . chunk_split(base64_encode($decoded['attStmt']['x5c'][0]), 64, "\n")
    . "-----END CERTIFICATE-----\n";
$nonceFromCert = NonceExtension::extract($credCertPem);

check('1. fmt', '= "' . $decoded['fmt'] . '"');
check('2. 憑證鏈', 'credCert ← intermediate ← root CA');
echo "\n";
line('  SHA256(challenge)', hex($clientDataHash));
line('  算出的 nonce', hex($expectedNonce));
line('  憑證裡的 nonce', hex($nonceFromCert));
line('  OID', NonceExtension::OID);
check('3. nonce', $expectedNonce === $nonceFromCert ? '兩者相符' : '不符！');
echo "\n";
check('4. keyId', 'SHA256(0x04‖X‖Y) = credentialId = client 宣告值');
check('5. App ID', 'rpIdHash = SHA256("' . APP_ID . '")');
check('6. counter', 'signCount = 0');
check('7. 環境', 'aaguid = "appattestdevelop"');

$response = $app->router->dispatch(new Request(
    'POST',
    '/attestation/register',
    [],
    (string) json_encode([
        'platform' => 'ios',
        'challengeId' => $challengeId,
        'keyId' => base64_encode($device->keyId()),
        'attestation' => base64_encode($attestation),
    ]),
));

$deviceId = (string) $response->payload['deviceId'];

echo "\n";
line('HTTP 狀態', (string) $response->status);
line('deviceId', $deviceId);
line('status', (string) $response->payload['status']);
echo "\n    後端存下 deviceId → (公鑰, counter=0)，並作廢這個 challengeId。\n";

// ---------------------------------------------------------------------
// 4. 受保護請求
// ---------------------------------------------------------------------

step('[4] 每次受保護請求');

/** 拿一個新的 challenge。 */
$newChallenge = static function () use ($app): array {
    $r = $app->router->dispatch(new Request(
        'POST',
        '/attestation/challenge',
        [],
        (string) json_encode(['platform' => 'ios']),
    ));

    return [
        'id' => (string) $r->payload['challengeId'],
        'value' => (string) Base64Url::decode((string) $r->payload['challenge']),
    ];
};

/** 組一個帶完整 attestation header 的請求。 */
$buildRequest = static function (
    string $deviceId,
    string $challengeId,
    string $requestHash,
    string $assertion,
    string $body,
): Request {
    return new Request('POST', '/protected/echo', [
        strtolower(AttestationGuard::HEADER_PLATFORM) => 'ios',
        strtolower(AttestationGuard::HEADER_DEVICE_ID) => $deviceId,
        strtolower(AttestationGuard::HEADER_CHALLENGE_ID) => $challengeId,
        strtolower(AttestationGuard::HEADER_REQUEST_HASH) => $requestHash,
        strtolower(AttestationGuard::HEADER_ASSERTION) => base64_encode($assertion),
    ], $body);
};

$c = $newChallenge();
$body = '{"message":"hello from the app"}';
$requestHash = RequestHash::compute('POST', '/protected/echo', $body, $c['value']);
$assertion = $device->assert($requestHash);

echo "    requestHash = base64url(SHA256( METHOD ‖ \\n ‖ path ‖ \\n ‖ SHA256(body) ‖ \\n ‖ challenge ))\n\n";
line('  method', 'POST');
line('  path', '/protected/echo');
line('  body', $body);
line('  SHA256(body)', hex(hash('sha256', $body, true)));
line('  challenge', hex($c['value']));
line('  → requestHash', $requestHash);

$assertionDecoded = CborDecoder::decode($assertion);
$authenticatorData = $assertionDecoded['authenticatorData'];

echo "\n    裝置用 Secure Enclave 裡的私鑰簽：\n\n";
line('  authenticatorData', strlen($authenticatorData) . ' bytes（註冊時是 ' . strlen($authData) . '，佈局不同）');
line('    signCount', (string) unpack('N', substr($authenticatorData, 33, 4))[1]);
line('  clientDataHash', hex(hash('sha256', $requestHash, true)));
line('  被簽的 nonce', hex(hash('sha256', $authenticatorData . hash('sha256', $requestHash, true), true)));
line('  signature', hex($assertionDecoded['signature']) . ' (DER)');

$response = $app->router->dispatch($buildRequest($deviceId, $c['id'], $requestHash, $assertion, $body));

echo "\n    後端：用存的公鑰驗簽章 → 自己重算 requestHash 比對 → counter 嚴格遞增\n\n";
line('HTTP 狀態', (string) $response->status);
line('回應', (string) json_encode($response->payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
line('裝置 counter', (string) $app->devices->get($deviceId)?->counter);

// ---------------------------------------------------------------------
// 5. 攻擊場景
// ---------------------------------------------------------------------

step('[5] 攻擊場景');

// --- 重放整個請求 ---
$c = $newChallenge();
$body = '{"message":"transfer 100"}';
$hash = RequestHash::compute('POST', '/protected/echo', $body, $c['value']);
$request = $buildRequest($deviceId, $c['id'], $hash, $device->assert($hash), $body);

$app->router->dispatch($request);                       // 第一次：正常通過
$replay = $app->router->dispatch($request);             // 一模一樣再送一次

blocked('重放整個合法請求', $replay, 'challengeId 是一次性的，第二次查不到可用的 challenge');

// --- 竄改 body ---
$c = $newChallenge();
$original = '{"amount":1}';
$hash = RequestHash::compute('POST', '/protected/echo', $original, $c['value']);
$assertion = $device->assert($hash);

$tampered = $app->router->dispatch(
    $buildRequest($deviceId, $c['id'], $hash, $assertion, '{"amount":1000000}'),
);

blocked('竄改 body（header 照舊）', $tampered, '後端用實際收到的 body 重算 requestHash，對不上 header');

// --- 竄改 body 並同步改 requestHash ---
$c = $newChallenge();
$assertion = $device->assert(RequestHash::compute('POST', '/protected/echo', '{"amount":1}', $c['value']));
$newBody = '{"amount":1000000}';
$newHash = RequestHash::compute('POST', '/protected/echo', $newBody, $c['value']);

$tampered2 = $app->router->dispatch($buildRequest($deviceId, $c['id'], $newHash, $assertion, $newBody));

blocked('竄改 body + 同步改 hash', $tampered2, 'hash 對上了，但簽章綁的是舊的 requestHash');

// --- counter 回放 ---
//
// 先成功送一次，讓伺服器記錄的 counter 追上裝置目前的值。前面幾個攻擊
// 雖然被擋，裝置端的 counter 仍然有往前跑（它每簽一次就加一），所以不
// 先同步的話，「重送舊值」反而會是一個伺服器沒看過的較大值 —— 那就不
// 構成回放了。
$c = $newChallenge();
$body = '{"message":"sync"}';
$hash = RequestHash::compute('POST', '/protected/echo', $body, $c['value']);
$app->router->dispatch($buildRequest($deviceId, $c['id'], $hash, $device->assert($hash), $body));

$counterBefore = (int) $app->devices->get($deviceId)?->counter;

$c = $newChallenge();
$body = '{"message":"replay"}';
$hash = RequestHash::compute('POST', '/protected/echo', $body, $c['value']);

$counterReplay = $app->router->dispatch(
    $buildRequest($deviceId, $c['id'], $hash, $device->assert($hash, [Flaw::COUNTER_REPLAY]), $body),
);

blocked('counter 回放', $counterReplay, "signCount 重送 {$counterBefore}，沒有大於已存的 {$counterBefore}");

// --- 另一台裝置冒名 ---
$attacker = new FakeDevice(APP_ID);
$c = $newChallenge();
$body = '{"message":"impersonation"}';
$hash = RequestHash::compute('POST', '/protected/echo', $body, $c['value']);

$impersonation = $app->router->dispatch(
    $buildRequest($deviceId, $c['id'], $hash, $attacker->assert($hash), $body),
);

blocked('用別台裝置的金鑰簽', $impersonation, 'deviceId 對應的公鑰驗不過這個簽章');

// --- 註冊階段：自簽 CA ---
$c = $newChallenge();
$rogue = new FakeDevice(APP_ID);

$rogueRegister = $app->router->dispatch(new Request('POST', '/attestation/register', [], (string) json_encode([
    'platform' => 'ios',
    'challengeId' => $c['id'],
    'keyId' => base64_encode($rogue->keyId()),
    'attestation' => base64_encode($rogue->attest($c['value'], [Flaw::BROKEN_CHAIN])),
])));

blocked('自己開 CA 簽假金鑰註冊', $rogueRegister, '憑證鏈結構正確，但接不回我們信任的 root CA');

// --- 註冊階段：別的 App ---
$c = $newChallenge();
$otherApp = new FakeDevice('ZZZZZ99999.com.someone.else');

$otherAppRegister = $app->router->dispatch(new Request('POST', '/attestation/register', [], (string) json_encode([
    'platform' => 'ios',
    'challengeId' => $c['id'],
    'keyId' => base64_encode($otherApp->keyId()),
    'attestation' => base64_encode($otherApp->attest($c['value'])),
])));

blocked('別的 App 的合法 attestation', $otherAppRegister, 'rpIdHash 不等於 SHA256(我們的 App ID)');

echo "\n";
echo "    \033[2m注意：以上每一個失敗回應都只是 {\"status\":\"rejected\"}。\033[0m\n";
echo "    \033[2m具體原因只寫進 server log —— 不給攻擊者當 oracle 用。\033[0m\n";
echo "\n";
