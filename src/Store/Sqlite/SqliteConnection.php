<?php

declare(strict_types=1);

namespace AppAttest\Store\Sqlite;

use PDO;
use RuntimeException;

/**
 * 建立 PDO 連線並確保 schema 存在。
 *
 * 用 SQLite 是因為 PHP 是 shared-nothing：每個 request 都是全新的
 * process，記憶體裡的東西下一個 request 就不見了。challenge 和 device
 * 一定得進外部儲存。
 *
 * 正式環境請換掉：challenge 適合放 Redis（天生有 TTL），device 放你們
 * 既有的資料庫。介面不變，只換實作。
 */
final class SqliteConnection
{
    public static function open(string $path): PDO
    {
        if ($path !== ':memory:') {
            $dir = dirname($path);

            if (!is_dir($dir) && !@mkdir($dir, 0o775, true) && !is_dir($dir)) {
                throw new RuntimeException("無法建立 SQLite 目錄：{$dir}");
            }
        }

        $pdo = new PDO('sqlite:' . $path, null, null, [
            // 出錯就拋例外，不要回 false 讓錯誤靜默往下流。
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // 關閉 emulated prepares，讓參數真的由 driver 綁定。
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        // WAL 讓讀不擋寫，多個 PHP process 併發時比較不會卡在鎖上。
        $pdo->exec('PRAGMA journal_mode = WAL');
        // 等鎖最多 5 秒再放棄，而不是立刻丟 SQLITE_BUSY。
        $pdo->exec('PRAGMA busy_timeout = 5000');

        self::migrate($pdo);

        return $pdo;
    }

    private static function migrate(PDO $pdo): void
    {
        // challenge 存 base64 而不是 BLOB：不同 PDO driver 對含 \x00 的
        // 二進位字串處理方式不一致，存成文字可以完全避開這類難查的問題。
        // 代價只是多幾個 byte。
        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS challenges (
                id          TEXT    PRIMARY KEY,
                platform    TEXT    NOT NULL,
                value_b64   TEXT    NOT NULL,
                expires_at  INTEGER NOT NULL,
                used_at     INTEGER
            )
        SQL);

        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges (expires_at)');

        $pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS devices (
                id             TEXT    PRIMARY KEY,
                platform       TEXT    NOT NULL,
                public_key_pem TEXT    NOT NULL,
                counter        INTEGER NOT NULL,
                created_at     INTEGER NOT NULL
            )
        SQL);
    }
}
