<?php

declare(strict_types=1);

namespace AppAttest\Tests\Unit;

use AppAttest\RequestHash;
use AppAttest\Tests\Fixture\FakeDevice;
use AppAttest\Tests\Fixture\Flaw;
use AppAttest\Tests\Support\TestEnv;
use AppAttest\Verification\Ios\AssertionValidator;
use AppAttest\Verification\Ios\AttestationValidator;
use AppAttest\Verification\Reason;
use AppAttest\Verification\VerificationFailure;
use PHPUnit\Framework\TestCase;

final class AssertionValidatorTest extends TestCase
{
    private AssertionValidator $validator;
    private FakeDevice $device;
    private string $publicKeyPem;
    private string $requestHash;

    protected function setUp(): void
    {
        $env = new TestEnv();
        $this->validator = new AssertionValidator($env->config);
        $this->device = new FakeDevice(TestEnv::APP_ID);

        // 先跑一次註冊，拿到 server 會存起來的那把公鑰。
        $challenge = random_bytes(32);
        $attestation = $this->device->attest($challenge);
        $validated = (new AttestationValidator($env->config))->validate(
            $attestation,
            $this->device->keyId(),
            $challenge,
            time(),
        );

        $this->publicKeyPem = $validated->publicKeyPem;
        $this->requestHash = RequestHash::compute('POST', '/protected/echo', '{"a":1}', random_bytes(32));
    }

    public function testValidAssertionPasses(): void
    {
        $assertion = $this->device->assert($this->requestHash);

        $newCounter = $this->validator->validate($assertion, $this->publicKeyPem, 0, $this->requestHash);

        self::assertSame(1, $newCounter);
    }

    /** 竄改簽章 → 拒絕。 */
    public function testTamperedSignatureIsRejected(): void
    {
        $assertion = $this->device->assert($this->requestHash, [Flaw::SIGNATURE]);

        $this->expectFailure(Reason::SIGNATURE_INVALID);

        $this->validator->validate($assertion, $this->publicKeyPem, 0, $this->requestHash);
    }

    /**
     * 別把 assertion 拿去配另一個請求。
     *
     * 這是「竄改 body」被擋下來的機制：body 一改，server 重算的
     * requestHash 就變了，而簽章是綁在舊的 requestHash 上。
     */
    public function testAssertionForAnotherRequestIsRejected(): void
    {
        $assertion = $this->device->assert($this->requestHash);
        $differentRequestHash = RequestHash::compute('POST', '/protected/echo', '{"a":999}', random_bytes(32));

        $this->expectFailure(Reason::SIGNATURE_INVALID);

        $this->validator->validate($assertion, $this->publicKeyPem, 0, $differentRequestHash);
    }

    /** 用別把金鑰的公鑰驗 → 拒絕。 */
    public function testAssertionFromAnotherDeviceIsRejected(): void
    {
        $otherDevice = new FakeDevice(TestEnv::APP_ID);
        $assertion = $otherDevice->assert($this->requestHash);

        $this->expectFailure(Reason::SIGNATURE_INVALID);

        $this->validator->validate($assertion, $this->publicKeyPem, 0, $this->requestHash);
    }

    /**
     * counter 必須**嚴格**遞增。
     *
     * 寫成 >= 的話這個測試會過，而 counter 這道防線等於不存在。
     */
    public function testEqualCounterIsRejected(): void
    {
        $assertion = $this->device->assert($this->requestHash);   // signCount = 1

        $this->expectFailure(Reason::COUNTER_NOT_INCREASING);

        // 已存的 counter 也是 1 → 相等，必須拒絕
        $this->validator->validate($assertion, $this->publicKeyPem, 1, $this->requestHash);
    }

    public function testLowerCounterIsRejected(): void
    {
        $assertion = $this->device->assert($this->requestHash);   // signCount = 1

        $this->expectFailure(Reason::COUNTER_NOT_INCREASING);

        $this->validator->validate($assertion, $this->publicKeyPem, 5, $this->requestHash);
    }

    /** counter 連續遞增時每次都該通過。 */
    public function testCounterIncrementsAcrossRequests(): void
    {
        $stored = 0;

        for ($i = 1; $i <= 5; $i++) {
            $hash = RequestHash::compute('POST', '/protected/echo', "{\"n\":{$i}}", random_bytes(32));
            $assertion = $this->device->assert($hash);

            $stored = $this->validator->validate($assertion, $this->publicKeyPem, $stored, $hash);

            self::assertSame($i, $stored);
        }
    }

    /** assertion 宣告了別人的 App ID → 拒絕（簽章本身是有效的）。 */
    public function testWrongAppIdIsRejected(): void
    {
        $assertion = $this->device->assert($this->requestHash, [Flaw::APP_ID]);

        $this->expectFailure(Reason::APP_ID_MISMATCH);

        $this->validator->validate($assertion, $this->publicKeyPem, 0, $this->requestHash);
    }

    public function testGarbageAssertionIsRejectedCleanly(): void
    {
        $this->expectFailure(Reason::BAD_CBOR);

        $this->validator->validate(random_bytes(40), $this->publicKeyPem, 0, $this->requestHash);
    }

    /** requestHash 比對：server 重算的結果與 header 不符就拒絕。 */
    public function testRequestHashMismatchIsRejected(): void
    {
        $challenge = random_bytes(32);

        $this->expectFailure(Reason::REQUEST_HASH_MISMATCH);

        AssertionValidator::requireMatchingRequestHash(
            requestHashFromClient: 'this-is-not-the-right-hash',
            method: 'POST',
            path: '/protected/echo',
            body: '{"a":1}',
            challenge: $challenge,
        );
    }

    public function testRequestHashMatchReturnsRecomputedValue(): void
    {
        $challenge = random_bytes(32);
        $expected = RequestHash::compute('POST', '/protected/echo', '{"a":1}', $challenge);

        $actual = AssertionValidator::requireMatchingRequestHash(
            requestHashFromClient: $expected,
            method: 'POST',
            path: '/protected/echo',
            body: '{"a":1}',
            challenge: $challenge,
        );

        self::assertSame($expected, $actual);
    }

    private function expectFailure(Reason $expected): void
    {
        $this->expectException(VerificationFailure::class);
        $this->expectExceptionMessageMatches('/^' . preg_quote($expected->value, '/') . '/');
    }
}
