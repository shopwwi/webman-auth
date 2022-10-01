[!['Build Status'](https://travis-ci.org/shopwwi/webman-auth.svg?branch=main)](https://github.com/shopwwi/webman-auth) [!['Latest Stable Version'](https://poser.pugx.org/shopwwi/webman-auth/v/stable.svg)](https://packagist.org/packages/shopwwi/webman-auth) [!['Total Downloads'](https://poser.pugx.org/shopwwi/webman-auth/d/total.svg)](https://packagist.org/packages/shopwwi/webman-auth) [!['License'](https://poser.pugx.org/shopwwi/webman-auth/license.svg)](https://packagist.org/packages/shopwwi/webman-auth)
# 安装

```
composer require shopwwi/webman-auth
```
# 配置文件
```
//路径 config/plugin/shopwwi/auth/app.php
// app_key 如果是laravel迁移过来的用户需与之前laravel的保持一致 如果是全新的 随意写个key即可
// jwt 配置项按自己需求配置即可 redis默认为false 如果要限制终端 则改为true
配置多用户

//初始化的示例 一定要改成自己实际的
'guard' => [
     'user' => [
         'key' => 'id', //主键
         'field' => ['id','name','email','mobile'], //设置允许写入扩展中的字段 一般为数据表存在的字段
         'num' => 0, //-1为不限制终端数量 0为只支持一个终端在线 大于0为同一账号同终端支持数量 建议设置为1 则同一账号同终端在线1个
         'model'=> app\model\Test::class
     ]
];
// 配置示例（根据自己真实情况 user一定要存在 因为默认就是user）
// field 是可以通过jwtKey解析出来的 请勿用敏感字段 以免信息泄露
'guard' => [
     'user' => [ // 普通用户
         'key' => 'id', //主键
         'field' => ['id','username','email','mobile','avatar'], //设置允许写入扩展中的字段 一般为数据表存在的字段
         'num' => 0, //-1为不限制终端数量 0为只支持一个终端在线 大于0为同一账号同终端支持数量 建议设置为1 则同一账号同终端在线1个
         'model'=> app\model\User::class //用户表模型
     ],
     'admin' => [ // 平台用户
         'key' => 'id', //主键
         'field' => ['id','name','avatar'], //设置允许写入扩展中的字段 一般为数据表存在的字段
         'num' => 0, //-1为不限制终端数量 0为只支持一个终端在线 大于0为同一账号同终端支持数量 建议设置为1 则同一账号同终端在线1个
         'model'=> app\model\Admin::class //管理员表模型
     ]
];
```
# 使用方法

1. 生成JWT密钥(命令行)

```
php webman shopwwi:auth

```
2. 加密密码

```php
use Shopwwi\WebmanAuth\Facade\Auth;

//不可逆转 只能用password_verify来判断正确与否
$password = '123456';
Auth::bcrypt($password);

```
3.自动对字段进行验证且登入

```php
use Shopwwi\WebmanAuth\Facade\Auth;

//验证字段一定得和设定得角色模型相匹配可以是任何字段组
// 这里自动进行了model查库操作 如果你的不支持 请用自定义登入
$tokenObject = Auth::attempt(['name'=> 'tycoonSong','password' => '123456']);

//返回对象$tokenObject 包含token_type,expires_in,refresh_expires_in,access_token,refresh_token
    
// 默认为user角色 当你是admin登入时
$tokenObject = Auth::guard('admin')->attempt(['name'=> 'tycoonSong','password' => '123456']);

```

4.自定义登入

```php
use Shopwwi\WebmanAuth\Facade\Auth;
use app\model\User;
use app\model\Admin;
//返回对象$tokenObject 包含token_type,expires_in,refresh_expires_in,access_token,refresh_token

$user = User::first();
$tokenObject = Auth::login($user);//$user可以是对象 同样可以是数组
    
    
// 默认为user角色 当你是admin登入时
$admin = Admin::first();
$tokenObject = Auth::guard('admin')->login($admin);

```

5.获取当前登入用户信息

```php
    use Shopwwi\WebmanAuth\Facade\Auth;
     $user = Auth::user(); //得到用户模型对象，查库数据，需查询动态数据时使用
     $user = Auth::user(true); // 得到扩展数据对象，非查库数据,比如只需得到用户ID或不常更新字段使用
     $admin = Auth::guard('admin')->user(); //当前登入管理员
 
```

6.退出登入

```php
    use Shopwwi\WebmanAuth\Facade\Auth;
     $logout = Auth::logout(); //退出当前用户
     $logout = Auth::logout(true); // 退出所有当前用户终端
     $logout = Auth::guard('admin')->logout(); //管理员退出
 
```

7.刷新当前登入用户token

```php
     use Shopwwi\WebmanAuth\Facade\Auth;
     $refresh = Auth::refresh();
     $refresh = Auth::guard('admin')->refresh(); //管理员刷新
 
```

8.单独设置过期时间

```php
use Shopwwi\WebmanAuth\Facade\Auth;
use app\model\User;
$user = User::first();
Auth::accessTime(3600)->refreshTime(360000)->login($user);
Auth::accessTime(3600)->refreshTime(360000)->attempt(['name'=> 'tycoonSong','password' => '123456']);
Auth::accessTime(3600)->refresh();

```

9.获取报错信息 Auth::fail();

```
    //默认设定是不会报错的 
    $user = Auth::user(); //当没有登入或异常时返回的null 用于用户可登入或可不登入场景里 只需要判断 $user == null 即可
    //而比如在会员中心调用时 
    $user = Auth::fail()->user(); //走的是异常处理类https://www.workerman.net/doc/webman/exception.html
```

- 开启redis后,建议开启

```
    // 在使用过程中我们通常一个接口允许多端使用的情况 那么默认设置是不限制使用端口的 
    // 可当你想允许比如web端同一账号只允许存在三个终端在线或同一账号APP只允许一个终端使用
    // 默认为web终端 传参client_type=web或你其它的终端client_type=ios
    //config/plugin/shopwwi/auth/app.php设置
    'guard' => [
         'user' => [ // 普通用户
             'key' => 'id', //主键
             'field' => ['id','username','email','mobile','avatar'], //设置允许写入扩展中的字段 一般为数据表存在的字段
             'num' => 0, //-1为不限制终端数量 0为只支持一个终端在线 大于0为同一账号同终端支持数量 建议设置为1 则同一账号同终端在线1个
             'model'=> app\model\User::class //用户表模型
         ]
     ]
     'jwt' => [
         'redis' => false,
         ....
      ]
     
    Auth::logout(true); // 退出所有当前用户终端
    
```
- 获取所有redis用户及终端状态
```
    // 你可以使用redis hash对终端在线更好的管理 比如对某个用户进行下线处理，或查询用户的token有效期
    // 具体业务自行根据需求去实现 本系统未对这方面业务进行封装
    $guard = 'user';
    Redis::hGetAll('token_'.$guard);
    // 用户编号为1 的 token下线清除 ，可以批量
    Redis::hDel('token_'.$guard,[1]);
```

- 直接调用jwt

```
    use Shopwwi\WebmanAuth\Facade\JWT as JwtFace;
    JwtFace::guard('user')->make($extend,$access_exp,$refresh_exp); //生成token 可为make($extend)
    JwtFace::guard('user')->refresh($accessTime = 0); //刷新令牌 可为refresh()
    JwtFace::guard('user')->verify($token); //$token可以不填则自动验证令牌 verify()
    JwtFace::guard('user')->getTokenExtend($token)//$token可以不填则自动验证令牌getTokenExtend()
```
