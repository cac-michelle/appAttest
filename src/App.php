<?php

declare(strict_types=1);

namespace AppAttest;

use AppAttest\Http\AttestationController;
use AppAttest\Http\AttestationGuard;
use AppAttest\Http\Logger;
use AppAttest\Http\ProtectedController;
use AppAttest\Http\Router;
use AppAttest\Store\ChallengeStore;
use AppAttest\Store\DeviceStore;
use AppAttest\Store\Sqlite\SqliteChallengeStore;
use AppAttest\Store\Sqlite\SqliteConnection;
use AppAttest\Store\Sqlite\SqliteDeviceStore;
use AppAttest\Verification\Ios\AssertionValidator;
use AppAttest\Verification\Ios\AttestationValidator;
use AppAttest\Verification\Ios\IosVerifier;
use AppAttest\Verification\VerifierRegistry;

/**
 * 把所有零件接起來。
 *
 * 一個地方就能看完整份相依關係圖 —— 換掉儲存實作、加一個平台驗證器，
 * 改的都是這裡。
 */
final class App
{
    public function __construct(
        public readonly Router $router,
        public readonly ChallengeStore $challenges,
        public readonly DeviceStore $devices,
        public readonly VerifierRegistry $registry,
    ) {
    }

    public static function create(Config $config, ?Logger $logger = null): self
    {
        $logger ??= new Logger();

        $pdo = SqliteConnection::open($config->sqlitePath);
        $challenges = new SqliteChallengeStore($pdo, $config->challengeTtlSeconds);
        $devices = new SqliteDeviceStore($pdo);

        // 目前只註冊 iOS。加 Android 時就是在這個陣列多一個元素，
        // 其餘程式碼一行都不用改。
        $registry = new VerifierRegistry([
            new IosVerifier(
                new AttestationValidator($config),
                new AssertionValidator($config),
                $challenges,
                $devices,
            ),
        ]);

        $guard = new AttestationGuard($registry, $logger);

        $router = new Router(
            new AttestationController($challenges, $registry, $logger),
            new ProtectedController(),
            $guard,
        );

        return new self($router, $challenges, $devices, $registry);
    }
}
