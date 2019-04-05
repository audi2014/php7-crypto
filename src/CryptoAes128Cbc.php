<?php namespace Audi2014\Crypto;

class CryptoAes128Cbc implements CryptoInterface {
    const ALGORITHM = "AES-128-CBC";

    private $privateKey;
    private $publicKey;


    /**
     * @return string
     */
    public function getAlgorithm() {
        return self::ALGORITHM;
    }

    /**
     * @return string
     */
    public function getPrivateKey() {
        return $this->privateKey;
    }

    /**
     * @return string
     */
    public function getPublicKey() {
        return $this->publicKey;
    }

    /**
     * CryptoAes128Cbc constructor.
     * @param string $privateKey
     * @param string $publicKey
     */
    public function __construct($privateKey, $publicKey) {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * @param int $strLength
     * @return string
     */
    public function generateToken($strLength = 32) {
        return bin2hex(openssl_random_pseudo_bytes($strLength / 2));
    }

    /**
     * @param string $password
     * @return string
     */
    public function createHash($password) {
        return password_hash($password, PASSWORD_DEFAULT);

    }

    /**
     * @param string $password
     * @param string $correctHash
     * @return bool
     */
    public function validatePassword($password, $correctHash) {
        return password_verify($password, $correctHash);

    }

    /**
     * @param string $plaintext
     * @return string
     */
    public function encrypt($plaintext) {
        $ivlen = openssl_cipher_iv_length(self::ALGORITHM);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($plaintext, self::ALGORITHM, $this->privateKey, $options = OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $ciphertext_raw, $this->privateKey, $as_binary = true);
        return base64_encode($iv . $hmac . $ciphertext_raw);
    }

    /**
     * @param string $ciphertext
     * @return null|string
     */
    public function decrypt($ciphertext) {
        $c = base64_decode($ciphertext);
        $ivlen = openssl_cipher_iv_length(self::ALGORITHM);
        $iv = substr($c, 0, $ivlen);
        $hmac = substr($c, $ivlen, $sha2len = 32);
        $ciphertext_raw = substr($c, $ivlen + $sha2len);
        $original_plaintext = openssl_decrypt($ciphertext_raw, self::ALGORITHM, $this->privateKey, $options = OPENSSL_RAW_DATA, $iv);
        $calcmac = hash_hmac('sha256', $ciphertext_raw, $this->privateKey, $as_binary = true);
        if (hash_equals($hmac, $calcmac))//с PHP 5.6+ сравнение, не подверженное атаке по времени
        {
            return $original_plaintext;
        } else {
            return null;
        }
    }

    /**
     * @param int $length
     * @return string
     */
    public function generateRandomString($length = 10) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }

    /**
     * @param int $length
     * @return string
     */
    public function generateRandomCode($length = 4) {
        $characters = '0123456789';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
}