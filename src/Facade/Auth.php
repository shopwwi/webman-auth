<?php

declare (strict_types = 1);
namespace Shopwwi\WebmanAuth\Facade;

/**
 * Class Auth
 * @package Shopwwi\WebmanAuth\Facade
 * @see \Shopwwi\WebmanAuth\Auth
 * @mixin \Shopwwi\WebmanAuth\Auth
 * @method guard(string $name) static 设置用户角色
 * @method login($data,int $access_time = 0,int $refresh_time = 0) static 登入
 * @method refresh() static 刷新token
 * @method logout() static 退出登入
 * @method fail(bool $error = true) static 抛出错误信息
 * @method attempt(array $data) static 字段检验登入
 * @method jwtKey() static 生成jwt密钥
 * @method bcrypt($password) static 密码加密
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
