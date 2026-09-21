<?php

declare(strict_types=1);

namespace AppAttest\Verification\Ios;

use AppAttest\Cbor\CborDecoder;
use AppAttest\Cbor\CborException;
use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;

/**
 * 解析 authenticator data。
 *
 * === 注意：註冊和每次請求的佈局不同 ===
 *
 * 註冊時（attestation 裡的 authData，含 attested credential data）：
 *
 *   offset  長度  欄位
 *   ------  ----  --------------------------------------------------
 *        0    32  rpIdHash            = SHA256(appId)
 *       32     1  flags
 *       33     4  signCount           big-endian，註冊時必為 0
 *       37    16  aaguid              環境識別
 *       53     2  credentialIdLength  big-endian，App Attest 固定為 32
 *       55    32  credentialId        = keyId
 *       87     …  credentialPublicKey COSE_Key 格式的 CBOR
 *
 * 每次請求時（assertion 裡的 authenticatorData）：
 *
 *   offset  長度  欄位
 *   ------  ----  --------------------------------------------------
 *        0    32  rpIdHash
 *       32     1  flags
 *       33     4  signCount           big-endian，必須嚴格遞增
 *
 *   總長剛好 37 bytes，**沒有** attested credential data。
 *
 * 混淆這兩種佈局是這個流程最常見的 bug：用註冊的解析器去讀 assertion，
 * 會在 offset 37 讀到越界；反過來則會把 aaguid 的前幾個 byte 當成別的
 * 東西。所以這裡刻意分成兩個具名的 static 方法，不做「自動判斷」。
 */
final class AuthData
{
    private const RP_ID_HASH_LENGTH = 32;
    private const FLAGS_OFFSET = 32;
    private const SIGN_COUNT_OFFSET = 33;

    /** assertion 的 authenticatorData 必須剛好這麼長。 */
    public const ASSERTION_LENGTH = 37;

    /** attestation 的 authData 在 COSE 公鑰之前的固定部分長度。 */
    private const ATTESTED_HEADER_LENGTH = 87;

    /** App Attest 的 credentialId 永遠是 32 bytes（就是 keyId）。 */
    private const CREDENTIAL_ID_LENGTH = 32;

    private function __construct(
        /** SHA256(appId)，32 bytes */
        public readonly string $rpIdHash,
        public readonly int $flags,
        public readonly int $signCount,
        /** 只有註冊時有值 */
        public readonly ?string $aaguid,
        /** 只有註冊時有值；等同 keyId */
        public readonly ?string $credentialId,
        /** 只有註冊時有值；COSE_Key 的 map */
        public readonly ?array $coseKeyMap,
        /** 原始位元組，算 nonce 時要用 */
        public readonly string $raw,
    ) {
    }

    /**
     * 解析註冊用的 authData（含 attested credential data）。
     *
     * @throws VerificationFailure
     */
    public static function parseForAttestation(string $raw): self
    {
        if (strlen($raw) <= self::ATTESTED_HEADER_LENGTH) {
            throw VerificationFailure::of(
                Reason::MALFORMED_AUTH_DATA,
                sprintf('authData 長度 %d，至少需要 %d + COSE 公鑰', strlen($raw), self::ATTESTED_HEADER_LENGTH),
            );
        }

        $credentialIdLength = self::uint16($raw, 53);

        if ($credentialIdLength !== self::CREDENTIAL_ID_LENGTH) {
            // 不是「照著長度欄位去讀」，而是直接要求它等於 32。App Attest
            // 的 keyId 就是 SHA-256，長度固定。接受其他長度等於讓攻擊者
            // 控制我們的讀取範圍。
            throw VerificationFailure::of(
                Reason::MALFORMED_AUTH_DATA,
                "credentialIdLength 應為 32，實際為 {$credentialIdLength}",
            );
        }

        $coseBytes = substr($raw, self::ATTESTED_HEADER_LENGTH);

        try {
            [$coseMap, $consumed] = CborDecoder::decodePrefix($coseBytes);
        } catch (CborException $e) {
            throw VerificationFailure::of(Reason::BAD_COSE_KEY, $e->getMessage());
        }

        // COSE 公鑰必須「剛好」用完 authData 剩下的空間。多出來的位元組
        // 代表有人在後面夾帶了東西，直接拒絕，不要只是忽略它。
        if ($consumed !== strlen($coseBytes)) {
            throw VerificationFailure::of(
                Reason::MALFORMED_AUTH_DATA,
                sprintf('COSE 公鑰之後還有 %d 個多餘位元組', strlen($coseBytes) - $consumed),
            );
        }

        if (!is_array($coseMap)) {
            throw VerificationFailure::of(Reason::BAD_COSE_KEY, 'COSE 公鑰不是 CBOR map');
        }

        return new self(
            rpIdHash: substr($raw, 0, self::RP_ID_HASH_LENGTH),
            flags: ord($raw[self::FLAGS_OFFSET]),
            signCount: self::uint32($raw, self::SIGN_COUNT_OFFSET),
            aaguid: substr($raw, 37, 16),
            credentialId: substr($raw, 55, self::CREDENTIAL_ID_LENGTH),
            coseKeyMap: $coseMap,
            raw: $raw,
        );
    }

    /**
     * 解析每次請求用的 authenticatorData（37 bytes，無 credential data）。
     *
     * @throws VerificationFailure
     */
    public static function parseForAssertion(string $raw): self
    {
        // 要求「剛好」37 bytes，而不是「至少」。assertion 的
        // authenticatorData 沒有可變長度的部分，多一個 byte 就是異常。
        if (strlen($raw) !== self::ASSERTION_LENGTH) {
            throw VerificationFailure::of(
                Reason::MALFORMED_AUTH_DATA,
                sprintf('assertion 的 authenticatorData 應為 %d bytes，實際 %d', self::ASSERTION_LENGTH, strlen($raw)),
            );
        }

        return new self(
            rpIdHash: substr($raw, 0, self::RP_ID_HASH_LENGTH),
            flags: ord($raw[self::FLAGS_OFFSET]),
            signCount: self::uint32($raw, self::SIGN_COUNT_OFFSET),
            aaguid: null,
            credentialId: null,
            coseKeyMap: null,
            raw: $raw,
        );
    }

    /** big-endian 無號 16 位元。 */
    private static function uint16(string $raw, int $offset): int
    {
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('n', substr($raw, $offset, 2));

        return $unpacked[1];
    }

    /** big-endian 無號 32 位元。 */
    private static function uint32(string $raw, int $offset): int
    {
        /** @var array{1: int} $unpacked */
        $unpacked = unpack('N', substr($raw, $offset, 4));

        return $unpacked[1];
    }
}
