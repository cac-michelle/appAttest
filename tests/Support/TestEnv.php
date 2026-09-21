<?php

declare(strict_types=1);

namespace AppAttest\Tests\Support;

use AppAttest\Config;
use AppAttest\Store\ChallengeStore;
use AppAttest\Store\DeviceStore;
use AppAttest\Store\Sqlite\SqliteChallengeStore;
use AppAttest\Store\Sqlite\SqliteConnection;
use AppAttest\Store\Sqlite\SqliteDeviceStore;
use AppAttest\Tests\Fixture\FakeAppleCa;
use AppAttest\Verification\Ios\AssertionValidator;
use AppAttest\Verification\Ios\AttestationValidator;
use AppAttest\Verification\Ios\IosVerifier;
use AppAttest\Verification\VerifierRegistry;

/**
 * 把整套東西接起來的測試用容器。
 *
 * 關鍵在 Config 的 rootCaPem 指向假 CA —— 除此之外，跑的完全是正式環境
 * 那份程式碼。SQLite 用 :memory:，每個測試一個乾淨的資料庫。
 */
final class TestEnv
{
    public const APP_ID = 'ABCDE12345.com.example.app';

    public readonly Config $config;
    public readonly ChallengeStore $challenges;
    public readonly DeviceStore $devices;
    public readonly VerifierRegistry $registry;
    public readonly IosVerifier $verifier;

    public function __construct(
        string $environment = Config::ENV_DEVELOPMENT,
        int $challengeTtlSeconds = 300,
    ) {
        $this->config = new Config(
            appId: self::APP_ID,
            environment: $environment,
            rootCaPem: FakeAppleCa::shared()->rootPem,
            challengeTtlSeconds: $challengeTtlSeconds,
            sqlitePath: ':memory:',
        );

        $pdo = SqliteConnection::open(':memory:');
        $this->challenges = new SqliteChallengeStore($pdo, $challengeTtlSeconds);
        $this->devices = new SqliteDeviceStore($pdo);

        $this->verifier = new IosVerifier(
            new AttestationValidator($this->config),
            new AssertionValidator($this->config),
            $this->challenges,
            $this->devices,
        );

        $this->registry = new VerifierRegistry([$this->verifier]);
    }
}
