<?php

declare(strict_types=1);

namespace AppAttest\Verification;

/**
 * 驗證失敗的原因代碼。
 *
 * === 重要：這些值永遠不可以回傳給 client ===
 *
 * 只寫進 log。對外一律只回 {"status":"rejected"} / HTTP 401。
 *
 * 理由：告訴攻擊者他卡在第幾關，等於免費提供一個 oracle。他可以逐步試出
 * 「憑證鏈過了但 nonce 沒過」，把攻擊從盲猜變成有導引的逼近。對合法的
 * client 來說這些細節也沒用 —— 正版 App 不會驗證失敗。
 *
 * 排查問題時看 server log，不要為了 debug 方便就把 reason 送出去，
 * 那個「暫時」的方便幾乎都會留在正式環境。
 */
enum Reason: string
{
    // --- challenge 生命週期 ---
    case CHALLENGE_NOT_FOUND = 'challenge_not_found';
    case CHALLENGE_EXPIRED = 'challenge_expired';
    case CHALLENGE_ALREADY_USED = 'challenge_already_used';

    // --- 結構解析 ---
    case BAD_CBOR = 'bad_cbor';
    case BAD_FMT = 'bad_fmt';
    case MALFORMED_AUTH_DATA = 'malformed_auth_data';
    case BAD_COSE_KEY = 'bad_cose_key';

    // --- 憑證 ---
    case CERT_CHAIN_INVALID = 'cert_chain_invalid';
    case CERT_EXPIRED = 'cert_expired';

    // --- Apple 規範的七項檢查 ---
    case NONCE_MISMATCH = 'nonce_mismatch';
    case KEY_ID_MISMATCH = 'key_id_mismatch';
    case APP_ID_MISMATCH = 'app_id_mismatch';
    case COUNTER_NOT_ZERO = 'counter_not_zero';
    case AAGUID_MISMATCH = 'aaguid_mismatch';

    // --- 每次請求 ---
    case DEVICE_NOT_FOUND = 'device_not_found';
    case REQUEST_HASH_MISMATCH = 'request_hash_mismatch';
    case SIGNATURE_INVALID = 'signature_invalid';
    case COUNTER_NOT_INCREASING = 'counter_not_increasing';

    // --- 路由 ---
    case UNSUPPORTED_PLATFORM = 'unsupported_platform';
}
