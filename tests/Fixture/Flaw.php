<?php

declare(strict_types=1);

namespace AppAttest\Tests\Fixture;

/**
 * 可以注入假裝置的瑕疵，每一項對應一種真實攻擊。
 *
 * 測試讀起來會像這樣：
 *
 *     $attestation = $device->attest($challenge, [Flaw::NONCE]);
 *     // → 應該被拒，reason = NONCE_MISMATCH
 *
 * 比起手動拼壞掉的位元組，這樣一眼就看得出在測什麼。
 */
enum Flaw
{
    /** attestation 宣告成別的格式。 */
    case FMT;

    /** credCert 裡的 nonce 不是 SHA256(authData ‖ SHA256(challenge))。攻擊：重放舊的 attestation。 */
    case NONCE;

    /** 憑證鏈接回一個我們不信任的 root。攻擊：自己開 CA 簽假金鑰。 */
    case BROKEN_CHAIN;

    /** rpIdHash 是別人的 App ID。攻擊：拿別的 App 的合法 attestation 來用。 */
    case APP_ID;

    /** 註冊時 signCount 不為 0。 */
    case COUNTER_NOT_ZERO;

    /** aaguid 是 production，但 server 設定為 development（或反之）。攻擊：開發版 App 打正式 API。 */
    case AAGUID;

    /** assertion 重送上一次的 counter。攻擊：重放先前的請求。 */
    case COUNTER_REPLAY;

    /** assertion 的簽章被竄改。 */
    case SIGNATURE;
}
