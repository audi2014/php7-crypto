<?php namespace Audi2014\Crypto;

interface CryptoInterface {
    /**
     * @return string
     */
    public function getPrivateKey();

    /**
     * @return string
     */
    public function getPublicKey();

    /**
     * @return string
     */
    public function getAlgorithm();

    /**
     * @param int $strLength
     * @return string
     */
    public function generateToken($strLength = 32);

    /**
     * @param string $password
     * @return string
     */
    public function createHash($password);

    /**
     * @param string $password
     * @param string $correctHash
     * @return boolean Returns TRUE if the password and hash match, or FALSE otherwise.
     */
    public function validatePassword($password, $correctHash);

    /**
     * @param string
     * @return string
     */
    public function encrypt($plaintext);

    /**
     * @param string $ciphertext
     * @return null|string
     */
    public function decrypt($ciphertext);

    /**
     * @param int $length
     * @return string
     */
    public function generateRandomString($length = 10);

    /**
     * @param int $length
     * @return string
     */
    public function generateRandomCode($length = 4);
}