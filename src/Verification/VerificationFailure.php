<?php

declare(strict_types=1);

namespace AppAttest\Verification;

use Exception;

/**
 * 內部用的例外，攜帶一個 Reason。
 *
 * === 為什麼驗證失敗用例外，對外卻用回傳值？ ===
 *
 * 註冊要跑七項檢查、每次請求要跑七個步驟。如果每一步都寫成
 *
 *     $result = $this->checkNonce(...);
 *     if (!$result->ok) { return $result; }
 *
 * 那實際的驗證邏輯會被錯誤處理淹沒，讀的人看不出主線在哪。用例外可以讓
 * 七項檢查寫成七行直線程式碼，一眼看完。
 *
 * 但例外只活在驗證器內部：IosVerifier 的 public 方法會把它接住，轉成
 * VerifyResult 回傳。**呼叫端永遠不需要 try/catch**，也就符合「驗證失敗
 * 是預期中的正常結果，不是異常」這個原則。
 *
 * 真正的程式錯誤（設定檔缺失、root CA 讀不到）用別的例外型別往上拋，
 * 那些才該讓請求 500，而不是靜默變成 rejected。
 */
final class VerificationFailure extends Exception
{
    public function __construct(
        public readonly Reason $reason,
        string $detail = '',
    ) {
        parent::__construct($detail !== '' ? "{$reason->value}: {$detail}" : $reason->value);
    }

    public static function of(Reason $reason, string $detail = ''): self
    {
        return new self($reason, $detail);
    }
}
