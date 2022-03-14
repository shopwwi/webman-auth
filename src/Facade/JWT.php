<?php

declare (strict_types = 1);
namespace Shopwwi\WebmanAuth\Facade;

/**
 * Class Auth
 * @package Shopwwi\WebmanAuth\Facade
 * @method \Shopwwi\WebmanAuth\JWT make(array $extend,int $access_exp = 0,int $refresh_exp = 0) static 生成令牌
 * @method \Shopwwi\WebmanAuth\JWT refresh(int $accessTime) static 刷新令牌
 * @method \Shopwwi\WebmanAuth\JWT guard($guard = 'user') static 设置角色
 * @method \Shopwwi\WebmanAuth\JWT verify(string $token = null, int $tokenType = 1) static 验证token
 * @method \Shopwwi\WebmanAuth\JWT verifyToken(string $token,int $tokenType) static 验证token值
 * @method \Shopwwi\WebmanAuth\JWT getTokenExtend(string $token = null, int $tokenType = 1) static 获取扩展字段
 * @method \Shopwwi\WebmanAuth\JWT makeToken(array $payload, string $secretKey, string $algorithms) static 生成token值
 * @method \Shopwwi\WebmanAuth\JWT logout($all = false) static 退出
 *
 */
class JWT
{
    protected static $_instance = null;


    public static function instance()
    {
        if (!static::$_instance) {
            static::$_instance = new \Shopwwi\WebmanAuth\JWT();
        }
        return static::$_instance;
    }
    /**
     * @param $name
     * @param $arguments
     * @return mixed
     */
    public static function __callStatic($name, $arguments)
    {
        return static::instance()->{$name}(... $arguments);
    }
}
