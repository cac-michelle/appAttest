<?php

declare(strict_types=1);

namespace AppAttest;

/**
 * 把一個 HTTP 請求綁定到一個 challenge 上。
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ 這是整個系統裡唯一一段「iOS 端必須逐位元組寫成一模一樣」的邏輯。 │
 * │ 改這裡就等於改 client 合約，兩邊必須同時改、同時發版。           │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * 算法：
 *
 *   requestHash = base64url_nopad(
 *       SHA256( method ‖ "\n" ‖ path ‖ "\n" ‖ SHA256(body) ‖ "\n" ‖ challenge )
 *   )
 *
 * 其中：
 *   method    大寫 ASCII，例如 "POST"
 *   path      不含 query string 的 URL path，例如 "/protected/echo"
 *   SHA256(body)  原始 body 位元組的 **raw binary** 摘要（32 bytes，不是 hex）
 *   challenge     challengeId 對應的 **原始 32 bytes**（不是 base64 字串）
 *   ‖         位元組串接
 *
 * 為什麼要把 challenge 混進去：這樣 requestHash 天生就綁死這一次的
 * challenge。攻擊者攔到一組合法的 (requestHash, assertion) 之後，沒辦法
 * 拿去配另一個 challenge 用 —— 而 challenge 是一次性的，所以整組憑證
 * 只能用一次。
 *
 * 為什麼要把 method 和 path 混進去：否則攔截者可以把一個打到
 * /protected/echo 的合法簽章，原封不動轉送到 /admin/delete-everything。
 * body 相同時簽章一樣會過。
 */
final class RequestHash
{
    /**
     * 算出一個請求的 requestHash。
     *
     * @param string $method    HTTP method，大寫
     * @param string $path      URL path，不含 query string，且必須是**未解碼**的形式
     * @param string $body      原始 request body（空 body 傳 ""）
     * @param string $challenge challenge 的原始 32 bytes
     *
     * === $path 一定要用未解碼的形式 ===
     *
     * client 送出的是 percent-encoded 的 path（線上實際傳的那份），所以
     * server 也必須用同一份去算。
     *
     *     parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)   // ✅ 未解碼
     *     urldecode(...)                                      // ❌ 解碼過就對不上
     *
     * 很多框架的 router 會貼心地幫你把 path 解碼後才交給 controller。若你
     * 們的框架是這樣，這裡要改成讀原始的 REQUEST_URI，否則只有含 %XX 或
     * 非 ASCII 的 URL 會驗不過，其他一切正常 —— 極難查。
     */
    public static function compute(string $method, string $path, string $body, string $challenge): string
    {
        $payload = strtoupper($method)
            . "\n"
            . $path
            . "\n"
            // 注意第三個參數 true：要的是 32 bytes 的 raw binary。
            // 漏掉就會變成 64 字元的 hex 字串，算出來的 hash 完全不同，
            // 而且症狀是「簽章明明對卻一直驗不過」，極難查。
            . hash('sha256', $body, true)
            . "\n"
            . $challenge;

        return Base64Url::encode(hash('sha256', $payload, true));
    }

    /**
     * 常數時間比對 client 送來的 requestHash 與 server 重算的結果。
     *
     * 用 hash_equals() 而不是 ===，避免比對耗時洩漏「前幾個字元對了」
     * 這種資訊。這裡的 timing 攻擊實際上很難打（值每次都不同），但這是
     * 一行就能做到的事，沒有理由不做。
     */
    public static function matches(string $fromClient, string $recomputed): bool
    {
        return hash_equals($recomputed, $fromClient);
    }
}
