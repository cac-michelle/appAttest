<?php

declare(strict_types=1);

namespace AppAttest\Tests\Unit;

use AppAttest\RequestHash;
use PHPUnit\Framework\TestCase;

final class RequestHashTest extends TestCase
{
    /**
     * 黃金測試向量。
     *
     * ┌──────────────────────────────────────────────────────────────┐
     * │ 這個測試壞掉 = iOS 端也必須同步改，否則所有請求都會被拒。    │
     * │ 不要為了讓它通過而改期望值 —— 先確認是不是真的要改合約。     │
     * └──────────────────────────────────────────────────────────────┘
     *
     * 期望值是用本實作產生後固定下來的。它的作用不是證明算法「正確」
     * （算法的定義就在規格裡），而是釘住它不被無意間改動。
     */
    public function testGoldenVector(): void
    {
        $challenge = str_repeat("\x01", 32);

        $hash = RequestHash::compute('POST', '/protected/echo', '{"message":"hi"}', $challenge);

        self::assertSame('C3jtWGVJfRayYTvpyQXdj283L3wlCMOHXarFy57mAns', $hash);
    }

    public function testEmptyBodyIsStable(): void
    {
        $challenge = str_repeat("\x02", 32);

        $hash = RequestHash::compute('GET', '/protected/ping', '', $challenge);

        self::assertSame('cpfTUEQgLO8Q_i3qFfIGITW7sh571H8yoFBKU5PpKWQ', $hash);
    }

    /** method 參與運算：攔截者不能把 POST 的簽章拿去用在 DELETE 上。 */
    public function testMethodChangesHash(): void
    {
        $challenge = random_bytes(32);

        self::assertNotSame(
            RequestHash::compute('POST', '/x', 'body', $challenge),
            RequestHash::compute('DELETE', '/x', 'body', $challenge),
        );
    }

    /** path 參與運算：不能把打到 /echo 的簽章轉送到 /admin。 */
    public function testPathChangesHash(): void
    {
        $challenge = random_bytes(32);

        self::assertNotSame(
            RequestHash::compute('POST', '/protected/echo', 'body', $challenge),
            RequestHash::compute('POST', '/admin/delete-all', 'body', $challenge),
        );
    }

    /** body 參與運算：這是「竄改內容」被擋下來的根本原因。 */
    public function testBodyChangesHash(): void
    {
        $challenge = random_bytes(32);

        self::assertNotSame(
            RequestHash::compute('POST', '/x', '{"amount":1}', $challenge),
            RequestHash::compute('POST', '/x', '{"amount":1000000}', $challenge),
        );
    }

    /** challenge 參與運算：同一個請求配不同 challenge 會得到不同 hash。 */
    public function testChallengeChangesHash(): void
    {
        self::assertNotSame(
            RequestHash::compute('POST', '/x', 'body', str_repeat("\x01", 32)),
            RequestHash::compute('POST', '/x', 'body', str_repeat("\x02", 32)),
        );
    }

    public function testMethodIsCaseInsensitive(): void
    {
        $challenge = random_bytes(32);

        self::assertSame(
            RequestHash::compute('post', '/x', 'body', $challenge),
            RequestHash::compute('POST', '/x', 'body', $challenge),
        );
    }

    public function testMatchesRejectsDifferentValue(): void
    {
        self::assertTrue(RequestHash::matches('abc', 'abc'));
        self::assertFalse(RequestHash::matches('abc', 'abd'));
        self::assertFalse(RequestHash::matches('', 'abc'));
    }

    /**
     * 輸出必須是 base64url 且無 padding —— 它要放進 HTTP header。
     */
    public function testOutputIsBase64UrlWithoutPadding(): void
    {
        for ($i = 0; $i < 20; $i++) {
            $hash = RequestHash::compute('POST', '/x', random_bytes(16), random_bytes(32));

            self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $hash);
            self::assertSame(43, strlen($hash), '32 bytes 的 base64url 無 padding 應為 43 字元');
        }
    }
}
