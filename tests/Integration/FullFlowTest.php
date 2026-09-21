<?php

declare(strict_types=1);

namespace AppAttest\Tests\Integration;

use AppAttest\App;
use AppAttest\Base64Url;
use AppAttest\Config;
use AppAttest\Http\AttestationGuard;
use AppAttest\Http\Logger;
use AppAttest\Http\Request;
use AppAttest\Http\Response;
use AppAttest\RequestHash;
use AppAttest\Tests\Fixture\FakeAppleCa;
use AppAttest\Tests\Fixture\FakeDevice;
use AppAttest\Tests\Fixture\Flaw;
use AppAttest\Tests\Support\TestEnv;
use PHPUnit\Framework\TestCase;

/**
 * 端到端：challenge → register → 受保護請求，以及三種攻擊被擋下。
 *
 * 走的是真正的 HTTP 路由與 controller，只有「憑證由假 CA 簽發」這一點
 * 與正式環境不同。
 */
final class FullFlowTest extends TestCase
{
    private App $app;
    private FakeDevice $device;

    protected function setUp(): void
    {
        $config = new Config(
            appId: TestEnv::APP_ID,
            environment: Config::ENV_DEVELOPMENT,
            rootCaPem: FakeAppleCa::shared()->rootPem,
            challengeTtlSeconds: 300,
            sqlitePath: ':memory:',
        );

        // 測試裡預期會有一堆拒絕，不要讓 log 淹沒輸出。
        $this->app = App::create($config, Logger::silent());
        $this->device = new FakeDevice(TestEnv::APP_ID);
    }

    // ---------------------------------------------------------------
    // 正常流程
    // ---------------------------------------------------------------

    public function testHappyPath(): void
    {
        $deviceId = $this->register();

        $body = '{"message":"hello"}';
        $response = $this->sendProtected($deviceId, $body);

        self::assertSame(200, $response->status);
        self::assertSame($deviceId, $response->payload['deviceId']);
        self::assertSame(['message' => 'hello'], $response->payload['echo']);
    }

    /** 連續多次請求都該通過，counter 一路遞增。 */
    public function testMultipleRequestsInSequence(): void
    {
        $deviceId = $this->register();

        for ($i = 1; $i <= 5; $i++) {
            $response = $this->sendProtected($deviceId, "{\"n\":{$i}}");

            self::assertSame(200, $response->status, "第 {$i} 次請求應該通過");
        }

        self::assertSame(5, $this->app->devices->get($deviceId)?->counter);
    }

    public function testChallengeEndpointReturnsUsableChallenge(): void
    {
        $response = $this->postJson('/attestation/challenge', ['platform' => 'ios']);

        self::assertSame(200, $response->status);
        self::assertSame(43, strlen($response->payload['challenge']), '32 bytes → 43 字元 base64url');
        self::assertNotEmpty($response->payload['challengeId']);
        self::assertMatchesRegularExpression(
            '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/',
            $response->payload['expiresAt'],
        );
    }

    /** 兩次要 challenge 不能拿到相同的值。 */
    public function testChallengesAreUnique(): void
    {
        $first = $this->postJson('/attestation/challenge', ['platform' => 'ios']);
        $second = $this->postJson('/attestation/challenge', ['platform' => 'ios']);

        self::assertNotSame($first->payload['challenge'], $second->payload['challenge']);
        self::assertNotSame($first->payload['challengeId'], $second->payload['challengeId']);
    }

    // ---------------------------------------------------------------
    // 攻擊場景
    // ---------------------------------------------------------------

    /**
     * 攻擊一：重放。
     *
     * 攔截一個完整合法的請求（含 assertion 和 challengeId），原封不動
     * 再送一次。擋住它的是 challengeId 的一次性。
     */
    public function testReplayingAWholeRequestIsRejected(): void
    {
        $deviceId = $this->register();

        $challenge = $this->issueChallenge();
        $body = '{"message":"transfer money"}';
        $requestHash = RequestHash::compute('POST', '/protected/echo', $body, $challenge['value']);
        $assertion = $this->device->assert($requestHash);

        $request = $this->protectedRequest($deviceId, $challenge['id'], $requestHash, $assertion, $body);

        $first = $this->app->router->dispatch($request);
        $replay = $this->app->router->dispatch($request);

        self::assertSame(200, $first->status);
        self::assertSame(401, $replay->status, '同一個 challengeId 不能用第二次');
        self::assertSame('rejected', $replay->payload['status']);
    }

    /**
     * 攻擊二：竄改 body。
     *
     * 攔截者保留合法的 assertion 和 header，只改 body。server 用**實際
     * 收到的 body** 重算 requestHash，算出來的值跟簽章綁定的不同。
     */
    public function testTamperingWithBodyIsRejected(): void
    {
        $deviceId = $this->register();

        $challenge = $this->issueChallenge();
        $originalBody = '{"amount":1}';
        $requestHash = RequestHash::compute('POST', '/protected/echo', $originalBody, $challenge['value']);
        $assertion = $this->device->assert($requestHash);

        // header 全部照舊，只換 body。
        $tampered = $this->protectedRequest(
            $deviceId,
            $challenge['id'],
            $requestHash,
            $assertion,
            '{"amount":1000000}',
        );

        self::assertSame(401, $this->app->router->dispatch($tampered)->status);
    }

    /**
     * 攻擊二之二：連 requestHash header 也一起改成新 body 的正確值。
     *
     * 這次 server 重算的 hash 會跟 header 相符 —— 但簽章是簽在舊的
     * requestHash 上，所以簽章驗不過。兩道檢查互相補位。
     */
    public function testTamperingWithBodyAndHashIsStillRejected(): void
    {
        $deviceId = $this->register();

        $challenge = $this->issueChallenge();
        $assertion = $this->device->assert(
            RequestHash::compute('POST', '/protected/echo', '{"amount":1}', $challenge['value']),
        );

        $newBody = '{"amount":1000000}';
        $newHash = RequestHash::compute('POST', '/protected/echo', $newBody, $challenge['value']);

        $tampered = $this->protectedRequest($deviceId, $challenge['id'], $newHash, $assertion, $newBody);

        self::assertSame(401, $this->app->router->dispatch($tampered)->status);
    }

    /**
     * 攻擊三：counter 回放。
     *
     * 裝置重送一個用過的 counter 值。即使配上新的 challenge、新的簽章，
     * counter 嚴格遞增的檢查也會擋下來。
     */
    public function testCounterReplayIsRejected(): void
    {
        $deviceId = $this->register();

        // 先正常跑一次，讓 server 的 counter 變成 1。
        self::assertSame(200, $this->sendProtected($deviceId, '{"n":1}')->status);

        // 這次用 COUNTER_REPLAY：裝置不遞增，重送 signCount = 1。
        $response = $this->sendProtected($deviceId, '{"n":2}', [Flaw::COUNTER_REPLAY]);

        self::assertSame(401, $response->status);
        self::assertSame(1, $this->app->devices->get($deviceId)?->counter, 'counter 不該被寫壞');
    }

    /** 換一台沒註冊過的裝置來簽 → 簽章驗不過。 */
    public function testAssertionFromUnregisteredDeviceIsRejected(): void
    {
        $deviceId = $this->register();

        $attacker = new FakeDevice(TestEnv::APP_ID);
        $challenge = $this->issueChallenge();
        $body = '{"message":"hi"}';
        $requestHash = RequestHash::compute('POST', '/protected/echo', $body, $challenge['value']);

        $request = $this->protectedRequest(
            $deviceId,                         // 宣告是合法裝置
            $challenge['id'],
            $requestHash,
            $attacker->assert($requestHash),   // 但用攻擊者的金鑰簽
            $body,
        );

        self::assertSame(401, $this->app->router->dispatch($request)->status);
    }

    public function testUnknownDeviceIdIsRejected(): void
    {
        $this->register();

        $response = $this->sendProtected('00000000-0000-4000-8000-000000000000', '{"a":1}');

        self::assertSame(401, $response->status);
    }

    /** 沒有任何 attestation header 的請求直接被擋。 */
    public function testRequestWithoutHeadersIsRejected(): void
    {
        $request = new Request('POST', '/protected/echo', [], '{"a":1}');

        self::assertSame(401, $this->app->router->dispatch($request)->status);
    }

    // ---------------------------------------------------------------
    // 註冊階段的拒絕
    // ---------------------------------------------------------------

    public function testRegisterWithBadAttestationIsRejected(): void
    {
        $challenge = $this->issueChallenge();

        $response = $this->postJson('/attestation/register', [
            'platform' => 'ios',
            'challengeId' => $challenge['id'],
            'keyId' => base64_encode($this->device->keyId()),
            'attestation' => base64_encode($this->device->attest($challenge['value'], [Flaw::NONCE])),
        ]);

        self::assertSame(401, $response->status);
        self::assertNull($response->payload['deviceId']);
        self::assertSame('rejected', $response->payload['status']);
    }

    /**
     * 註冊失敗也會消耗掉 challenge。
     *
     * 刻意的：讓攻擊者沒辦法拿同一個 challenge 反覆試不同的 attestation，
     * 每試一次都得重新跟 server 要。
     */
    public function testFailedRegistrationStillConsumesChallenge(): void
    {
        $challenge = $this->issueChallenge();

        $this->postJson('/attestation/register', [
            'platform' => 'ios',
            'challengeId' => $challenge['id'],
            'keyId' => base64_encode($this->device->keyId()),
            'attestation' => base64_encode($this->device->attest($challenge['value'], [Flaw::NONCE])),
        ]);

        // 同一個 challengeId 再送一份完全合法的 attestation，也該被拒。
        $second = $this->postJson('/attestation/register', [
            'platform' => 'ios',
            'challengeId' => $challenge['id'],
            'keyId' => base64_encode($this->device->keyId()),
            'attestation' => base64_encode($this->device->attest($challenge['value'])),
        ]);

        self::assertSame(401, $second->status);
    }

    /** 錯誤回應不可以洩漏是哪一關沒過。 */
    public function testRejectionLeaksNoReason(): void
    {
        $challenge = $this->issueChallenge();

        $response = $this->postJson('/attestation/register', [
            'platform' => 'ios',
            'challengeId' => $challenge['id'],
            'keyId' => base64_encode($this->device->keyId()),
            'attestation' => base64_encode($this->device->attest($challenge['value'], [Flaw::BROKEN_CHAIN])),
        ]);

        self::assertSame(['deviceId' => null, 'status' => 'rejected'], $response->payload);

        $serialised = json_encode($response->payload);
        self::assertStringNotContainsString('cert', (string) $serialised);
        self::assertStringNotContainsString('chain', (string) $serialised);
        self::assertStringNotContainsString('nonce', (string) $serialised);
    }

    // ---------------------------------------------------------------
    // 平台路由
    // ---------------------------------------------------------------

    /** Android 還沒實作：challenge 階段就擋掉，不會落到任何驗證器。 */
    public function testAndroidPlatformIsNotSupportedYet(): void
    {
        $response = $this->postJson('/attestation/challenge', ['platform' => 'android']);

        self::assertSame(400, $response->status);
        self::assertSame('unsupported_platform', $response->payload['error']);
    }

    /** 把 platform 改成不存在的值也只是被路由擋掉。 */
    public function testUnknownPlatformOnProtectedRequestIsRejected(): void
    {
        $deviceId = $this->register();
        $challenge = $this->issueChallenge();
        $body = '{"a":1}';
        $requestHash = RequestHash::compute('POST', '/protected/echo', $body, $challenge['value']);

        $request = new Request('POST', '/protected/echo', [
            strtolower(AttestationGuard::HEADER_PLATFORM) => 'windows-phone',
            strtolower(AttestationGuard::HEADER_DEVICE_ID) => $deviceId,
            strtolower(AttestationGuard::HEADER_CHALLENGE_ID) => $challenge['id'],
            strtolower(AttestationGuard::HEADER_REQUEST_HASH) => $requestHash,
            strtolower(AttestationGuard::HEADER_ASSERTION) => base64_encode($this->device->assert($requestHash)),
        ], $body);

        self::assertSame(401, $this->app->router->dispatch($request)->status);
    }

    // ---------------------------------------------------------------
    // 輔助方法
    // ---------------------------------------------------------------

    /** 跑完註冊流程，回傳 deviceId。 */
    private function register(): string
    {
        $challenge = $this->issueChallenge();

        $response = $this->postJson('/attestation/register', [
            'platform' => 'ios',
            'challengeId' => $challenge['id'],
            'keyId' => base64_encode($this->device->keyId()),
            'attestation' => base64_encode($this->device->attest($challenge['value'])),
        ]);

        self::assertSame(200, $response->status, '註冊應該成功');
        self::assertSame('trusted', $response->payload['status']);

        return (string) $response->payload['deviceId'];
    }

    /** @return array{id: string, value: string} */
    private function issueChallenge(): array
    {
        $response = $this->postJson('/attestation/challenge', ['platform' => 'ios']);

        return [
            'id' => (string) $response->payload['challengeId'],
            'value' => (string) Base64Url::decode((string) $response->payload['challenge']),
        ];
    }

    /** @param list<Flaw> $flaws */
    private function sendProtected(string $deviceId, string $body, array $flaws = []): Response
    {
        $challenge = $this->issueChallenge();
        $requestHash = RequestHash::compute('POST', '/protected/echo', $body, $challenge['value']);
        $assertion = $this->device->assert($requestHash, $flaws);

        return $this->app->router->dispatch(
            $this->protectedRequest($deviceId, $challenge['id'], $requestHash, $assertion, $body),
        );
    }

    private function protectedRequest(
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
    }

    /** @param array<string, mixed> $payload */
    private function postJson(string $path, array $payload): Response
    {
        return $this->app->router->dispatch(
            new Request('POST', $path, ['content-type' => 'application/json'], (string) json_encode($payload)),
        );
    }
}
