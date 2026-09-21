<?php

declare(strict_types=1);

namespace AppAttest\Store\Sqlite;

use AppAttest\Store\Device;
use AppAttest\Store\DeviceStore;
use PDO;

final class SqliteDeviceStore implements DeviceStore
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function create(string $platform, string $publicKeyPem, int $now): string
    {
        $id = Uuid::v4();

        $stmt = $this->pdo->prepare(
            'INSERT INTO devices (id, platform, public_key_pem, counter, created_at)
             VALUES (:id, :platform, :pem, 0, :now)',
        );

        $stmt->execute([
            ':id' => $id,
            ':platform' => $platform,
            ':pem' => $publicKeyPem,
            ':now' => $now,
        ]);

        return $id;
    }

    public function get(string $deviceId): ?Device
    {
        $stmt = $this->pdo->prepare(
            'SELECT id, platform, public_key_pem, counter FROM devices WHERE id = :id',
        );

        $stmt->execute([':id' => $deviceId]);
        $row = $stmt->fetch();

        if ($row === false) {
            return null;
        }

        return new Device(
            id: (string) $row['id'],
            platform: (string) $row['platform'],
            publicKeyPem: (string) $row['public_key_pem'],
            counter: (int) $row['counter'],
        );
    }

    public function updateCounter(string $deviceId, int $newCounter): bool
    {
        // 條件式更新：WHERE counter < :new。
        //
        // 兩個併發請求帶著同一個 signCount 打進來時，兩個都可能通過
        // AssertionValidator 的檢查（它們各自讀到的 storedCounter 相同），
        // 但只有一個能在這裡成功寫入。
        //
        // 寫成無條件的 SET counter = :new 會讓 counter 可能不減反增地
        // 倒退，等於把這道防線關掉。
        $stmt = $this->pdo->prepare(
            'UPDATE devices SET counter = :new WHERE id = :id AND counter < :new',
        );

        $stmt->execute([':id' => $deviceId, ':new' => $newCounter]);

        return $stmt->rowCount() === 1;
    }
}
