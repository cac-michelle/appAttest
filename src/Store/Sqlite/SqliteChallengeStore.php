<?php

declare(strict_types=1);

namespace AppAttest\Store\Sqlite;

use AppAttest\Store\Challenge;
use AppAttest\Store\ChallengeStore;
use PDO;

final class SqliteChallengeStore implements ChallengeStore
{
    private const CHALLENGE_BYTES = 32;

    public function __construct(
        private readonly PDO $pdo,
        private readonly int $ttlSeconds,
    ) {
    }

    public function issue(string $platform, int $now): Challenge
    {
        // random_bytes() 是密碼學安全的亂數來源。**不要**用 rand()、
        // mt_rand() 或 uniqid() —— 那些是可預測的，攻擊者能預先算出下一個
        // challenge，整個一次性機制就沒意義了。
        $value = random_bytes(self::CHALLENGE_BYTES);
        $id = Uuid::v4();
        $expiresAt = $now + $this->ttlSeconds;

        $stmt = $this->pdo->prepare(
            'INSERT INTO challenges (id, platform, value_b64, expires_at, used_at)
             VALUES (:id, :platform, :value, :expires_at, NULL)',
        );

        $stmt->execute([
            ':id' => $id,
            ':platform' => $platform,
            ':value' => base64_encode($value),
            ':expires_at' => $expiresAt,
        ]);

        return new Challenge($id, $platform, $value, $expiresAt);
    }

    public function consume(string $challengeId, int $now): ?Challenge
    {
        // ┌──────────────────────────────────────────────────────────────┐
        // │ 一次性消耗的關鍵：用一道帶條件的 UPDATE，靠 affected rows     │
        // │ 判斷是不是「我」搶到的。                                      │
        // └──────────────────────────────────────────────────────────────┘
        //
        // 「未使用」和「未過期」兩個條件都寫在 WHERE 裡，由資料庫在單一
        // 原子操作中判定。兩個併發請求同時打進來，只有一個會拿到
        // rowCount() === 1，另一個拿到 0。
        //
        // 反例（**不要這樣寫**）：
        //     $row = SELECT ... WHERE id = ? AND used_at IS NULL;
        //     if ($row) { UPDATE ... SET used_at = ?; return $row; }
        // 兩個請求會同時通過 SELECT，兩個都回傳成功。
        //
        // 換 Redis 時對應 GETDEL 或 Lua script；換 MySQL 時是同樣的
        // UPDATE ... WHERE 搭配 affected rows。
        $update = $this->pdo->prepare(
            'UPDATE challenges
                SET used_at = :now
              WHERE id = :id
                AND used_at IS NULL
                AND expires_at > :now',
        );

        $update->execute([':id' => $challengeId, ':now' => $now]);

        if ($update->rowCount() !== 1) {
            // 不存在 / 已用過 / 已過期，三者對呼叫端沒有差別。
            return null;
        }

        $select = $this->pdo->prepare(
            'SELECT id, platform, value_b64, expires_at FROM challenges WHERE id = :id',
        );

        $select->execute([':id' => $challengeId]);
        $row = $select->fetch();

        if ($row === false) {
            return null;
        }

        return new Challenge(
            id: (string) $row['id'],
            platform: (string) $row['platform'],
            value: (string) base64_decode((string) $row['value_b64'], true),
            expiresAt: (int) $row['expires_at'],
        );
    }

    public function purgeExpired(int $now): int
    {
        // 已使用的 challenge 也要清，但要留一段時間 —— 立刻刪掉的話，
        // 重放攻擊會從「已使用」變成「不存在」，兩者都會被拒絕，但 log
        // 上看不出是哪一種，少了一個偵測攻擊的訊號。
        $stmt = $this->pdo->prepare('DELETE FROM challenges WHERE expires_at < :cutoff');
        $stmt->execute([':cutoff' => $now - 86400]);

        return $stmt->rowCount();
    }
}
