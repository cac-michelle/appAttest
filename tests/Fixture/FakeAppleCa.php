<?php

declare(strict_types=1);

namespace AppAttest\Tests\Fixture;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use RuntimeException;

/**
 * 自簽的假 Apple CA：root → intermediate。
 *
 * === 為什麼這樣就足以測試真正的驗證邏輯 ===
 *
 * 驗證程式碼裡沒有任何一行寫死「Apple」。信任錨點是 Config::$rootCaPem
 * 傳進來的一份 PEM。測試時傳這裡產生的假 root，正式環境傳 Apple 官方的
 * root —— **跑的是同一段程式碼**。
 *
 * 所以這些測試涵蓋的就是正式環境會執行的邏輯，不是一個平行的簡化版本。
 * 唯一沒被測到的是「Apple 真的簽了這份憑證」，而那恰好是我們無法、也
 * 不需要在單元測試裡驗證的部分。
 *
 * 憑證產生一次就快取在 process 裡 —— 產生 EC 金鑰和簽憑證都不快，
 * 每個 test case 重做一次會讓測試慢到沒人想跑。
 */
final class FakeAppleCa
{
    private static ?self $instance = null;
    private static ?self $rogue = null;

    private int $nextSerial = 100;

    private function __construct(
        public readonly OpenSSLAsymmetricKey $rootKey,
        public readonly OpenSSLCertificate $rootCert,
        public readonly string $rootPem,
        public readonly OpenSSLAsymmetricKey $intermediateKey,
        public readonly OpenSSLCertificate $intermediateCert,
        public readonly string $intermediateDer,
        private readonly string $workDir,
    ) {
    }

    public static function shared(): self
    {
        return self::$instance ??= self::create();
    }

    /**
     * 一組跟 shared() 完全無關的 CA。
     *
     * 用來製造「憑證鏈本身有效，但接不回我們信任的 root」的攻擊場景 ——
     * 這正是攻擊者自己開一間 CA 來簽假金鑰時會發生的事。
     */
    public static function rogue(): self
    {
        return self::$rogue ??= self::create();
    }

    private static function create(): self
    {
        $workDir = sys_get_temp_dir() . '/appattest-fixture-' . getmypid();

        if (!is_dir($workDir) && !mkdir($workDir, 0o700, true) && !is_dir($workDir)) {
            throw new RuntimeException("無法建立夾具暫存目錄：{$workDir}");
        }

        $cnf = self::writeConfig($workDir, 'ca.cnf', null);

        $rootKey = self::newEcKey($cnf);
        $rootCsr = openssl_csr_new(['commonName' => 'Fake App Attest Root CA'], $rootKey, [
            'config' => $cnf,
            'digest_alg' => 'sha256',
        ]);

        if ($rootCsr === false) {
            throw new RuntimeException('產生 root CSR 失敗：' . openssl_error_string());
        }

        // 自簽：把 CA 憑證參數傳 null 代表用自己的金鑰簽自己。
        $rootCert = openssl_csr_sign($rootCsr, null, $rootKey, 3650, [
            'config' => $cnf,
            'digest_alg' => 'sha256',
            'x509_extensions' => 'v3_ca',
        ], 1);

        if ($rootCert === false) {
            throw new RuntimeException('簽 root 憑證失敗：' . openssl_error_string());
        }

        $intermediateKey = self::newEcKey($cnf);
        $intermediateCsr = openssl_csr_new(['commonName' => 'Fake App Attest CA 1'], $intermediateKey, [
            'config' => $cnf,
            'digest_alg' => 'sha256',
        ]);

        if ($intermediateCsr === false) {
            throw new RuntimeException('產生 intermediate CSR 失敗：' . openssl_error_string());
        }

        $intermediateCert = openssl_csr_sign($intermediateCsr, $rootCert, $rootKey, 1825, [
            'config' => $cnf,
            'digest_alg' => 'sha256',
            'x509_extensions' => 'v3_ca',
        ], 2);

        if ($intermediateCert === false) {
            throw new RuntimeException('簽 intermediate 憑證失敗：' . openssl_error_string());
        }

        openssl_x509_export($rootCert, $rootPem);

        return new self(
            rootKey: $rootKey,
            rootCert: $rootCert,
            rootPem: $rootPem,
            intermediateKey: $intermediateKey,
            intermediateCert: $intermediateCert,
            intermediateDer: self::certToDer($intermediateCert),
            workDir: $workDir,
        );
    }

    /**
     * 簽一張 credCert，並把 nonce 寫進 Apple 的自訂 extension。
     *
     * 真實世界裡這是 Apple 的 CA 做的事：它在簽發 credCert 時把
     * SHA256(authData ‖ SHA256(challenge)) 埋進 OID 1.2.840.113635.100.8.2。
     *
     * @param OpenSSLAsymmetricKey        $deviceKey 裝置金鑰（credCert 要包它的公鑰）
     * @param string                      $nonce     32 bytes
     * @param OpenSSLCertificate|null     $issuer    預設用 intermediate 簽；傳別的可以製造斷鏈
     * @param OpenSSLAsymmetricKey|null   $issuerKey 對應的私鑰
     */
    public function signCredCert(
        OpenSSLAsymmetricKey $deviceKey,
        string $nonce,
        ?OpenSSLCertificate $issuer = null,
        ?OpenSSLAsymmetricKey $issuerKey = null,
    ): OpenSSLCertificate {
        // DER: SEQUENCE { [1] { OCTET STRING nonce } }
        $extensionDer = "\x30\x24\xA1\x22\x04\x20" . $nonce;
        $cnf = self::writeConfig($this->workDir, 'leaf-' . $this->nextSerial . '.cnf', $extensionDer);

        $csr = openssl_csr_new(['commonName' => 'Fake App Attest Credential'], $deviceKey, [
            'config' => $cnf,
            'digest_alg' => 'sha256',
        ]);

        if ($csr === false) {
            throw new RuntimeException('產生 credCert CSR 失敗：' . openssl_error_string());
        }

        $cert = openssl_csr_sign(
            $csr,
            $issuer ?? $this->intermediateCert,
            $issuerKey ?? $this->intermediateKey,
            365,
            [
                'config' => $cnf,
                'digest_alg' => 'sha256',
                'x509_extensions' => 'v3_leaf',
            ],
            $this->nextSerial++,
        );

        if ($cert === false) {
            throw new RuntimeException('簽 credCert 失敗：' . openssl_error_string());
        }

        return $cert;
    }

    public static function newEcKey(?string $configPath = null): OpenSSLAsymmetricKey
    {
        $args = [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ];

        if ($configPath !== null) {
            $args['config'] = $configPath;
        }

        $key = openssl_pkey_new($args);

        if ($key === false) {
            throw new RuntimeException('產生 EC 金鑰失敗：' . openssl_error_string());
        }

        return $key;
    }

    public static function certToDer(OpenSSLCertificate $cert): string
    {
        openssl_x509_export($cert, $pem);

        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem) ?? '';

        return (string) base64_decode($body, true);
    }

    /** 寫一份 openssl.cnf；$leafExtensionDer 為 null 時不含 nonce extension。 */
    private static function writeConfig(string $dir, string $name, ?string $leafExtensionDer): string
    {
        $leafSection = "[ v3_leaf ]\nbasicConstraints = critical,CA:FALSE\n";

        if ($leafExtensionDer !== null) {
            // OpenSSL 設定檔可以用 DER:XX:XX:… 直接寫入任意 OID 的原始位元組，
            // 這正是塞進 Apple 自訂 extension 的方法。
            $hex = implode(':', str_split(strtoupper(bin2hex($leafExtensionDer)), 2));
            $leafSection .= '1.2.840.113635.100.8.2 = DER:' . $hex . "\n";
        }

        $contents = <<<CNF
        [ req ]
        distinguished_name = dn
        prompt = no

        [ dn ]
        CN = placeholder

        [ v3_ca ]
        basicConstraints = critical,CA:TRUE
        keyUsage = critical,keyCertSign,cRLSign

        {$leafSection}
        CNF;

        $path = $dir . '/' . $name;
        file_put_contents($path, $contents);

        return $path;
    }
}
