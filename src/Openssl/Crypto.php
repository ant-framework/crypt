<?php
namespace Ant\Crypto\Openssl;

use RuntimeException;
use InvalidArgumentException;

/**
 * todo 支持Aead加密
 *
 * Class Openssl
 * @package Ant\Ciphers
 */
class Crypto
{
    protected $method;

    protected $key;

    protected $iv;

    /**
     * Openssl constructor.
     * @param $method
     * @param $key
     * @param $iv
     */
    public function __construct($method, $key, $iv)
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException("请安装openssl扩展");
        }

        $ciphers = openssl_get_cipher_methods();

        if (!in_array($method, $ciphers)) {
            throw new InvalidArgumentException("Invalid cipher name [{$method}]");
        }

        $this->method = $method;
        $this->key = $key;
        $this->iv = $iv;
    }

    /**
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @return int
     */
    public function getIvLength()
    {
        return strlen($this->iv);
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @return int
     */
    public function getKeyLength()
    {
        return strlen($this->key);
    }

    /**
     * @param $data
     * @return string
     */
    public function encrypt($data)
    {
        return openssl_encrypt($data, $this->method, $this->key, OPENSSL_RAW_DATA, $this->iv);
    }

    /**
     * @param $data
     * @return string
     */
    public function decrypt($data)
    {
        return openssl_decrypt($data, $this->method, $this->key, OPENSSL_RAW_DATA, $this->iv);
    }
}