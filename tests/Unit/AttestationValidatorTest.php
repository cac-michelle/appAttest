<?php

declare(strict_types=1);

namespace AppAttest\Tests\Unit;

use AppAttest\Config;
use AppAttest\Tests\Fixture\FakeDevice;
use AppAttest\Tests\Fixture\Flaw;
use AppAttest\Tests\Support\TestEnv;
use AppAttest\Verification\Ios\AttestationValidator;
use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;
use PHPUnit\Framework\TestCase;

/**
 * Apple 規範的七項註冊檢查，每項各一個「會過」和「會被擋」的案例。
 *
 * 這些測試直接打 AttestationValidator，不經過資料庫 —— 純位元組進、
 * 結果出。要理解某一項檢查在防什麼，看對應的測試最快。
 */
final class AttestationValidatorTest extends TestCase
{
    private AttestationValidator $validator;
    private FakeDevice $device;
    private string $challenge;
    private int $now;

    protected function setUp(): void
    {
        $env = new TestEnv();
        $this->validator = new AttestationValidator($env->config);
        $this->device = new FakeDevice(TestEnv::APP_ID);
        $this->challenge = random_bytes(32);
        $this->now = time();
    }

    /** 一份完全合法的 attestation 必須通過，並吐出可用的公鑰。 */
    public function testValidAttestationPasses(): void
    {
        $attestation = $this->device->attest($this->challenge);

        $result = $this->validator->validate(
            $attestation,
            $this->device->keyId(),
            $this->challenge,
            $this->now,
        );

        self::assertSame($this->device->keyId(), $result->keyId);
        self::assertStringContainsString('BEGIN PUBLIC KEY', $result->publicKeyPem);
        self::assertNotFalse(
            openssl_pkey_get_public($result->publicKeyPem),
            '抽出來的公鑰必須能被 OpenSSL 載入',
        );
    }

    /** 檢查 1：fmt 必須是 apple-appattest。 */
    public function testWrongFmtIsRejected(): void
    {
        $this->assertRejects(Reason::BAD_FMT, [Flaw::FMT]);
    }

    /**
     * 檢查 2：憑證鏈必須接回設定的 root CA。
     *
     * 攻擊場景：任何人都能開一間 CA，簽出結構完全正確的憑證鏈。擋住他的
     * 唯一理由是那條鏈接不回 Apple 的 root。
     */
    public function testChainToUntrustedRootIsRejected(): void
    {
        $this->assertRejects(Reason::CERT_CHAIN_INVALID, [Flaw::BROKEN_CHAIN]);
    }

    /**
     * 檢查 3：nonce 必須等於 SHA256(authData ‖ SHA256(challenge))。
     *
     * 這是把 attestation 綁定到「這一次的 challenge」的唯一機制。少了它，
     * 攔截到的 attestation 可以無限重放。
     */
    public function testWrongNonceIsRejected(): void
    {
        $this->assertRejects(Reason::NONCE_MISMATCH, [Flaw::NONCE]);
    }

    /** 檢查 3 的另一面：對的 attestation 配錯的 challenge 也要被擋。 */
    public function testAttestationReplayedWithDifferentChallengeIsRejected(): void
    {
        $attestation = $this->device->attest($this->challenge);
        $anotherChallenge = random_bytes(32);

        $this->expectFailure(Reason::NONCE_MISMATCH);

        $this->validator->validate(
            $attestation,
            $this->device->keyId(),
            $anotherChallenge,
            $this->now,
        );
    }

    /** 檢查 4：client 宣告的 keyId 必須等於公鑰的 SHA-256。 */
    public function testMismatchedKeyIdIsRejected(): void
    {
        $attestation = $this->device->attest($this->challenge);

        $this->expectFailure(Reason::KEY_ID_MISMATCH);

        $this->validator->validate(
            $attestation,
            random_bytes(32),   // 不是這把金鑰的 keyId
            $this->challenge,
            $this->now,
        );
    }

    /**
     * 檢查 5：App ID 必須相符。
     *
     * 攻擊場景：另一個 App 的開發者拿自己完全合法的 attestation 來打我們
     * 的 API。憑證鏈會過、nonce 會過 —— 擋住他的是 App ID。
     */
    public function testWrongAppIdIsRejected(): void
    {
        $this->assertRejects(Reason::APP_ID_MISMATCH, [Flaw::APP_ID]);
    }

    /** 檢查 6：註冊時 counter 必須為 0。 */
    public function testNonZeroCounterIsRejected(): void
    {
        $this->assertRejects(Reason::COUNTER_NOT_ZERO, [Flaw::COUNTER_NOT_ZERO]);
    }

    /**
     * 檢查 7：環境必須相符。
     *
     * 攻擊場景：用 TestFlight 或開發版 App（可被除錯器附加、可改記憶體）
     * 產生的 attestation 去打正式環境 API。
     */
    public function testWrongEnvironmentIsRejected(): void
    {
        $this->assertRejects(Reason::AAGUID_MISMATCH, [Flaw::AAGUID]);
    }

    /** 反過來：正式環境設定不接受 development 的 attestation。 */
    public function testDevelopmentAttestationRejectedByProductionConfig(): void
    {
        $env = new TestEnv(Config::ENV_PRODUCTION);
        $validator = new AttestationValidator($env->config);

        $this->expectFailure(Reason::AAGUID_MISMATCH);

        $validator->validate(
            $this->device->attest($this->challenge),
            $this->device->keyId(),
            $this->challenge,
            $this->now,
        );
    }

    /** 垃圾輸入不能讓驗證器爆掉，要乾淨地回報失敗。 */
    public function testGarbageInputIsRejectedCleanly(): void
    {
        $this->expectFailure(Reason::BAD_CBOR);

        $this->validator->validate(
            random_bytes(64),
            $this->device->keyId(),
            $this->challenge,
            $this->now,
        );
    }

    public function testEmptyInputIsRejectedCleanly(): void
    {
        $this->expectFailure(Reason::BAD_CBOR);

        $this->validator->validate('', $this->device->keyId(), $this->challenge, $this->now);
    }

    /** @param list<Flaw> $flaws */
    private function assertRejects(Reason $expected, array $flaws): void
    {
        $this->expectFailure($expected);

        $this->validator->validate(
            $this->device->attest($this->challenge, $flaws),
            $this->device->keyId(),
            $this->challenge,
            $this->now,
        );
    }

    private function expectFailure(Reason $expected): void
    {
        $this->expectException(VerificationFailure::class);
        $this->expectExceptionMessageMatches('/^' . preg_quote($expected->value, '/') . '/');
    }
}
