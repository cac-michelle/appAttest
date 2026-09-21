<?php

declare(strict_types=1);

namespace AppAttest\Tests\Integration;

use AppAttest\Base64Url;
use AppAttest\Http\AttestationGuard;
use AppAttest\RequestHash;
use AppAttest\Tests\Fixture\FakeAppleCa;
use AppAttest\Tests\Fixture\FakeDevice;
use AppAttest\Tests\Support\TestEnv;
use PHPUnit\Framework\TestCase;

/**
 * 在真正的 HTTP server（php -S）上跑完整流程。
 *
 * === 為什麼需要這一層，FullFlowTest 還不夠？ ===
 *
 * FullFlowTest 直接呼叫 Router，跑在 CLI SAPI 底下。有一整類的 bug 只在
 * 網頁 SAPI 才會出現，那種測試永遠看不到。
 *
 * 實際踩過的例子：Logger 原本用 fwrite(STDERR, …)。STDERR 這個常數只有
 * CLI 才定義，在 php-fpm / 內建 server 底下會 fatal error。而 logger 只在
 * **驗證失敗時**被呼叫 —— 所以本該回 401 的請求變成了帶 HTML 錯誤頁的
 * 200。CLI 測試全綠，正式環境的拒絕路徑整個壞掉。
 *
 * 這個測試還涵蓋 Request::fromGlobals()：HTTP_X_ATTEST_* 的 header 名稱
 * 轉換、php://input 讀 body、以及從 REQUEST_URI 去掉 query string。
 * 這些在直接建構 Request 物件時全都被繞過了。
 */
final class HttpServerTest extends TestCase
{
    private const HOST = '127.0.0.1';
    private const PORT = 8731;

    /** @var resource|null */
    private static $serverProcess = null;
    private static string $workDir = '';
    private FakeDevice $device;

    public static function setUpBeforeClass(): void
    {
        self::$workDir = sys_get_temp_dir() . '/appattest-http-' . getmypid();
        @mkdir(self::$workDir, 0o700, true);

        // server 是另一個 process，拿不到我們記憶體裡的假 CA —— 把 root
        // 憑證寫成檔案傳過去。這正是正式環境的做法（只是換成 Apple 的）。
        $rootPath = self::$workDir . '/root.pem';
        file_put_contents($rootPath, FakeAppleCa::shared()->rootPem);

        $sqlitePath = self::$workDir . '/attest.sqlite';
        @unlink($sqlitePath);

        $docRoot = dirname(__DIR__, 2) . '/public';
        $command = sprintf(
            'APP_ID=%s APPLE_ROOT_CA_PEM=%s SQLITE_PATH=%s exec php -S %s:%d -t %s',
            escapeshellarg(TestEnv::APP_ID),
            escapeshellarg($rootPath),
            escapeshellarg($sqlitePath),
            self::HOST,
            self::PORT,
            escapeshellarg($docRoot),
        );

        $descriptors = [1 => ['file', self::$workDir . '/server.log', 'a'], 2 => ['file', self::$workDir . '/server.log', 'a']];
        self::$serverProcess = proc_open($command, $descriptors, $pipes);

        self::waitForServer();
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$serverProcess)) {
            proc_terminate(self::$serverProcess);
            proc_close(self::$serverProcess);
        }
    }

    protected function setUp(): void
    {
        $this->device = new FakeDevice(TestEnv::APP_ID);
    }

    public function testFullFlowOverRealHttp(): void
    {
        $deviceId = $this->register();

        $body = '{"message":"over real http"}';
        [$status, $payload] = $this->sendProtected($deviceId, '/protected/echo', $body);

        self::assertSame(200, $status);
        self::assertSame($deviceId, $payload['deviceId']);
        self::assertSame(['message' => 'over real http'], $payload['echo']);
    }

    /**
     * 拒絕路徑必須真的回 401。
     *
     * 這就是抓到 STDERR bug 的那個測試 —— 拒絕會觸發 logger，logger 一炸
     * 就整個 request 掛掉，狀態碼變成別的東西。
     */
    public function testRejectedRequestReturns401OverHttp(): void
    {
        [$status, $payload] = $this->request('POST', '/protected/echo', [], '{"a":1}');

        self::assertSame(401, $status, '沒有 attestation header 必須回 401，不是 200 或 500');
        self::assertSame(['deviceId' => null, 'status' => 'rejected'], $payload);
    }

    /** 註冊失敗同樣會觸發 logger。 */
    public function testRejectedRegistrationReturns401OverHttp(): void
    {
        $challenge = $this->issueChallenge();

        [$status, $payload] = $this->request('POST', '/attestation/register', [], (string) json_encode([
            'platform' => 'ios',
            'challengeId' => $challenge['id'],
            'keyId' => base64_encode($this->device->keyId()),
            'attestation' => base64_encode(random_bytes(64)),   // 垃圾
        ]));

        self::assertSame(401, $status);
        self::assertSame('rejected', $payload['status']);
    }

    /**
     * query string 必須被排除在 requestHash 之外。
     *
     * Request::fromGlobals() 用 parse_url() 取 path。漏掉那一步的話，所有
     * 帶 query 的請求都會驗不過 —— 而這在直接建構 Request 的測試裡看不到。
     */
    public function testQueryStringIsExcludedFromRequestHash(): void
    {
        $deviceId = $this->register();

        [$status] = $this->sendProtected($deviceId, '/protected/echo?trace=1&lang=zh-TW', '{"a":1}');

        self::assertSame(200, $status, '帶 query string 的請求也該通過');
    }

    /** 重放整個請求，經過真實 HTTP 仍然要被擋。 */
    public function testReplayOverHttpIsRejected(): void
    {
        $deviceId = $this->register();

        $challenge = $this->issueChallenge();
        $body = '{"message":"replay me"}';
        $hash = RequestHash::compute('POST', '/protected/echo', $body, $challenge['value']);
        $headers = $this->attestHeaders($deviceId, $challenge['id'], $hash, $this->device->assert($hash));

        [$first] = $this->request('POST', '/protected/echo', $headers, $body);
        [$replay] = $this->request('POST', '/protected/echo', $headers, $body);

        self::assertSame(200, $first);
        self::assertSame(401, $replay);
    }

    // ---------------------------------------------------------------

    private function register(): string
    {
        $challenge = $this->issueChallenge();

        [$status, $payload] = $this->request('POST', '/attestation/register', [], (string) json_encode([
            'platform' => 'ios',
            'challengeId' => $challenge['id'],
            'keyId' => base64_encode($this->device->keyId()),
            'attestation' => base64_encode($this->device->attest($challenge['value'])),
        ]));

        self::assertSame(200, $status, '註冊應該成功');

        return (string) $payload['deviceId'];
    }

    /** @return array{id: string, value: string} */
    private function issueChallenge(): array
    {
        [, $payload] = $this->request('POST', '/attestation/challenge', [], '{"platform":"ios"}');

        return [
            'id' => (string) $payload['challengeId'],
            'value' => (string) Base64Url::decode((string) $payload['challenge']),
        ];
    }

    /** @return array{0: int, 1: array<string, mixed>} */
    private function sendProtected(string $deviceId, string $pathWithQuery, string $body): array
    {
        $challenge = $this->issueChallenge();

        // requestHash 用的是不含 query string 的 path。
        $path = (string) (parse_url($pathWithQuery, PHP_URL_PATH) ?: '/');
        $hash = RequestHash::compute('POST', $path, $body, $challenge['value']);

        return $this->request(
            'POST',
            $pathWithQuery,
            $this->attestHeaders($deviceId, $challenge['id'], $hash, $this->device->assert($hash)),
            $body,
        );
    }

    /** @return array<string, string> */
    private function attestHeaders(string $deviceId, string $challengeId, string $hash, string $assertion): array
    {
        return [
            AttestationGuard::HEADER_PLATFORM => 'ios',
            AttestationGuard::HEADER_DEVICE_ID => $deviceId,
            AttestationGuard::HEADER_CHALLENGE_ID => $challengeId,
            AttestationGuard::HEADER_REQUEST_HASH => $hash,
            AttestationGuard::HEADER_ASSERTION => base64_encode($assertion),
        ];
    }

    /**
     * @param array<string, string> $headers
     *
     * @return array{0: int, 1: array<string, mixed>}
     */
    private function request(string $method, string $path, array $headers, string $body): array
    {
        $lines = ['Content-Type: application/json'];

        foreach ($headers as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }

        $context = stream_context_create(['http' => [
            'method' => $method,
            'header' => implode("\r\n", $lines),
            'content' => $body,
            'ignore_errors' => true,   // 4xx 也要拿到 body，不要變成 false
            'timeout' => 5,
        ]]);

        $url = sprintf('http://%s:%d%s', self::HOST, self::PORT, $path);
        $raw = @file_get_contents($url, false, $context);

        self::assertNotFalse($raw, "請求 {$path} 沒有拿到回應");

        $status = 0;

        foreach (self::responseHeaders() as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d+)#', $line, $m) === 1) {
                $status = (int) $m[1];
            }
        }

        $decoded = json_decode((string) $raw, true);

        self::assertIsArray(
            $decoded,
            "回應不是 JSON（可能是 PHP 錯誤頁）：" . substr((string) $raw, 0, 400),
        );

        return [$status, $decoded];
    }

    /** @return list<string> */
    private static function responseHeaders(): array
    {
        // PHP 8.4 起 $http_response_header 被標為 deprecated，改用新函式。
        if (function_exists('http_get_last_response_headers')) {
            return http_get_last_response_headers() ?? [];
        }

        return $GLOBALS['http_response_header'] ?? [];
    }

    private static function waitForServer(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $socket = @fsockopen(self::HOST, self::PORT, $errno, $errstr, 0.1);

            if ($socket !== false) {
                fclose($socket);

                return;
            }

            usleep(50_000);
        }

        self::fail('內建 HTTP server 沒有在時限內啟動');
    }
}
