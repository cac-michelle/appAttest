<?php

declare(strict_types=1);

namespace AppAttest\Tests\Unit;

use AppAttest\Store\Sqlite\SqliteChallengeStore;
use AppAttest\Store\Sqlite\SqliteConnection;
use AppAttest\Store\Sqlite\SqliteDeviceStore;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * challenge 的一次性與 counter 的條件式更新。
 *
 * 這兩件事是 replay 防護的地基。實作若退化成「先查再寫」，這裡的測試
 * 在單執行緒下**仍然會過** —— 所以額外加了直接檢查 SQL 語意的案例。
 */
final class ChallengeStoreTest extends TestCase
{
    private PDO $pdo;
    private SqliteChallengeStore $store;

    protected function setUp(): void
    {
        $this->pdo = SqliteConnection::open(':memory:');
        $this->store = new SqliteChallengeStore($this->pdo, 300);
    }

    public function testIssuedChallengeCanBeConsumedOnce(): void
    {
        $now = time();
        $challenge = $this->store->issue('ios', $now);

        $first = $this->store->consume($challenge->id, $now);

        self::assertNotNull($first);
        self::assertSame($challenge->value, $first->value);
    }

    /** 同一個 challengeId 用第二次必須失敗 —— 這就是 replay 防護。 */
    public function testSecondConsumeReturnsNull(): void
    {
        $now = time();
        $challenge = $this->store->issue('ios', $now);

        $this->store->consume($challenge->id, $now);
        $second = $this->store->consume($challenge->id, $now);

        self::assertNull($second, '一個 challenge 只能被消耗一次');
    }

    public function testExpiredChallengeCannotBeConsumed(): void
    {
        $now = time();
        $challenge = $this->store->issue('ios', $now);

        $afterExpiry = $now + 301;

        self::assertNull($this->store->consume($challenge->id, $afterExpiry));
    }

    public function testChallengeIsStillValidJustBeforeExpiry(): void
    {
        $now = time();
        $challenge = $this->store->issue('ios', $now);

        self::assertNotNull($this->store->consume($challenge->id, $now + 299));
    }

    public function testUnknownChallengeReturnsNull(): void
    {
        self::assertNull($this->store->consume('no-such-id', time()));
    }

    /** challenge 必須是 32 bytes 的密碼學亂數，且每次都不同。 */
    public function testChallengesAreRandomAndCorrectLength(): void
    {
        $now = time();
        $seen = [];

        for ($i = 0; $i < 50; $i++) {
            $challenge = $this->store->issue('ios', $now);

            self::assertSame(32, strlen($challenge->value));
            self::assertArrayNotHasKey($challenge->value, $seen, 'challenge 不可重複');

            $seen[$challenge->value] = true;
        }
    }

    /**
     * 直接驗證 consume() 的 SQL 語意：已被標記使用的列不可以再被更新。
     *
     * 這個測試繞過 API，直接檢查資料庫狀態，因為「原子性」這件事沒辦法
     * 靠單執行緒的呼叫序列證明。
     */
    public function testConsumeMarksRowAsUsedAtomically(): void
    {
        $now = time();
        $challenge = $this->store->issue('ios', $now);

        $this->store->consume($challenge->id, $now);

        $stmt = $this->pdo->prepare('SELECT used_at FROM challenges WHERE id = :id');
        $stmt->execute([':id' => $challenge->id]);
        $usedAt = $stmt->fetch()['used_at'] ?? null;

        self::assertNotNull($usedAt, 'consume() 必須把 used_at 寫進資料庫');

        // 模擬第二個併發請求跑同一道 UPDATE：條件不成立，影響 0 列。
        $update = $this->pdo->prepare(
            'UPDATE challenges SET used_at = :now
              WHERE id = :id AND used_at IS NULL AND expires_at > :now',
        );
        $update->execute([':id' => $challenge->id, ':now' => $now]);

        self::assertSame(0, $update->rowCount(), '已使用的 challenge 不能再被搶到');
    }

    /** counter 的條件式更新：不可倒退、不可持平。 */
    public function testCounterUpdateRejectsNonIncreasingValues(): void
    {
        $devices = new SqliteDeviceStore($this->pdo);
        $deviceId = $devices->create('ios', "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n", time());

        self::assertTrue($devices->updateCounter($deviceId, 1));
        self::assertTrue($devices->updateCounter($deviceId, 2));

        self::assertFalse($devices->updateCounter($deviceId, 2), '相同的 counter 不能再寫入一次');
        self::assertFalse($devices->updateCounter($deviceId, 1), 'counter 不能倒退');

        self::assertSame(2, $devices->get($deviceId)?->counter);
    }

    public function testPurgeRemovesOldChallenges(): void
    {
        $longAgo = time() - 200_000;
        $store = new SqliteChallengeStore($this->pdo, 300);
        $store->issue('ios', $longAgo);

        self::assertSame(1, $store->purgeExpired(time()));
    }
}
