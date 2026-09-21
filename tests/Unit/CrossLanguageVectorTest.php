<?php

declare(strict_types=1);

namespace AppAttest\Tests\Unit;

use AppAttest\RequestHash;
use PHPUnit\Framework\TestCase;

/**
 * 跨語言合約測試（後端側）。
 *
 * ┌──────────────────────────────────────────────────────────────────┐
 * │ 驗證的檔案跟 iOS 端是同一份：                                    │
 * │   ios/Tests/AppAttestClientTests/Fixtures/request-hash-vectors.json │
 * └──────────────────────────────────────────────────────────────────┘
 *
 * iOS 端有一個對稱的測試（`CrossLanguageVectorTests.swift`）。所以：
 *
 *   - 改了 PHP 的算法   → 這個測試紅
 *   - 改了 Swift 的算法 → iOS 那個測試紅
 *   - 想改合約          → 必須重新產生向量檔，兩邊測試同時更新
 *
 * 光有「兩邊各自寫一個相同的期望值」是不夠的 —— 那只能證明兩邊都抄對了
 * 那兩個值。這份檔案有 80 組案例，涵蓋空 body、4KB body、含 null byte 的
 * body、中文與 emoji、percent-encoded 的 path、被編碼的斜線，也就是兩種
 * 語言最容易產生歧異的地方。
 *
 * 向量檔由 PHP 這一側產生（見 tools/generate-request-hash-vectors.php），
 * PHP 是合約的權威來源。
 */
final class CrossLanguageVectorTest extends TestCase
{
    private const VECTORS_PATH = __DIR__
        . '/../../ios/Tests/AppAttestClientTests/Fixtures/request-hash-vectors.json';

    /** @return list<array<string, string>> */
    private function loadVectors(): array
    {
        $raw = @file_get_contents(self::VECTORS_PATH);

        self::assertNotFalse($raw, '找不到向量檔：' . self::VECTORS_PATH);

        $decoded = json_decode((string) $raw, true);

        self::assertIsArray($decoded, '向量檔不是合法 JSON');

        return $decoded;
    }

    public function testAllVectorsMatch(): void
    {
        $vectors = $this->loadVectors();

        self::assertGreaterThan(50, count($vectors), '向量數量看起來不對');

        foreach ($vectors as $index => $vector) {
            $body = (string) base64_decode($vector['bodyBase64'], true);
            $challenge = (string) base64_decode($vector['challengeBase64'], true);

            $actual = RequestHash::compute(
                $vector['method'],
                $vector['path'],
                $body,
                $challenge,
            );

            self::assertSame(
                $vector['expected'],
                $actual,
                sprintf(
                    '案例 %d 不一致：method=%s path=%s body=%d bytes',
                    $index,
                    $vector['method'],
                    $vector['path'],
                    strlen($body),
                ),
            );
        }
    }

    /**
     * 向量檔必須真的涵蓋會讓兩種語言產生歧異的案例。
     *
     * 少了這個檢查，向量檔可能在某次重新產生時退化成一堆無聊的 ASCII
     * 案例，測試依然全綠，但實際上什麼都沒守住。
     */
    public function testVectorsCoverTrickyCases(): void
    {
        $vectors = $this->loadVectors();

        $paths = array_column($vectors, 'path');
        $bodies = array_map(
            static fn (array $v): string => (string) base64_decode($v['bodyBase64'], true),
            $vectors,
        );

        self::assertNotEmpty(
            array_filter($paths, static fn (string $p): bool => str_contains($p, '%')),
            '應該要有 percent-encoded 的 path',
        );
        self::assertContains('', $bodies, '應該要有空 body 的案例');
        self::assertNotEmpty(
            array_filter($bodies, static fn (string $b): bool => str_contains($b, "\x00")),
            '應該要有含 null byte 的 body',
        );
        self::assertNotEmpty(
            array_filter($bodies, static fn (string $b): bool => strlen($b) > 1000),
            '應該要有大 body 的案例',
        );
    }
}
