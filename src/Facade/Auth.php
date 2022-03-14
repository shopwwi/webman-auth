<?php

declare (strict_types = 1);
namespace Shopwwi\WebmanAuth\Facade;

/**
 * Class Auth
 * @package Shopwwi\WebmanAuth\Facade
 * @method \Shopwwi\WebmanAuth\Auth guard(string $name) static 设置用户角色
 * @method \Shopwwi\WebmanAuth\Auth login($data,int $access_time = 0,int $refresh_time = 0) static 登入
 * @method \Shopwwi\WebmanAuth\Auth refresh() static 刷新token
 * @method \Shopwwi\WebmanAuth\Auth logout() static 退出登入
 * @method \Shopwwi\WebmanAuth\Auth fail(bool $error = true) static 抛出错误信息
 * @method \Shopwwi\WebmanAuth\Auth attempt(array $data) static 字段检验登入
 * @method \Shopwwi\WebmanAuth\Auth jwtKey() static 生成jwt密钥
 * @method \Shopwwi\WebmanAuth\Auth bcrypt($password) static 密码加密
 */
class Auth
{
    protected static $_instance = null;


    public static function instance()
    {
        if (!static::$_instance) {
            static::$_instance = new \Shopwwi\WebmanAuth\Auth();
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
