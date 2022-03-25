<?php

declare (strict_types = 1);
namespace Shopwwi\WebmanAuth\Facade;

/**
 * Class Auth
 * @package Shopwwi\WebmanAuth\Facade
 * @see \Shopwwi\WebmanAuth\JWT
 * @mixin \Shopwwi\WebmanAuth\JWT
 * @method make(array $extend,int $access_exp = 0,int $refresh_exp = 0) static 生成令牌
 * @method refresh(int $accessTime) static 刷新令牌
 * @method guard($guard = 'user') static 设置角色
 * @method verify(string $token = null, int $tokenType = 1) static 验证token
 * @method verifyToken(string $token,int $tokenType) static 验证token值
 * @method getTokenExtend(string $token = null, int $tokenType = 1) static 获取扩展字段
 * @method makeToken(array $payload, string $secretKey, string $algorithms) static 生成token值
 * @method logout($all = false) static 退出
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
