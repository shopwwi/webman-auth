# 安装

```
composer require shopwwi/webman-auth
```
# 使用方法

1. 生成JWT密钥

```
use Shopwwi\WebmanAuth\Facade\Auth;

//在任意控制器里调用一次即可 比较懒没写命令 请原谅
Auth::jwtKey();

```
2. 加密密码

```
use Shopwwi\WebmanAuth\Facade\Auth;

//不可逆转 只能用password_verify来判断正确与否
Auth::bcrypt($password);

```
3.自动对字段进行验证且登入

```
use Shopwwi\WebmanAuth\Facade\Auth;

//验证字段一定得和设定得角色模型相匹配可以是任何字段组

    $tokenObject = Auth::attempt(['name'= 'tycoonSong','password' = '123456']);
    返回对象$tokenObject 包含token_type,expires_in,refresh_expires_in,access_token,refresh_token
    
// 默认为user角色 当你是admin登入时
$tokenObject = Auth::guard('admin')->attempt(['name'= 'tycoonSong','password' = '123456']);

```

4.自定义登入

```
use Shopwwi\WebmanAuth\Facade\Auth;

返回对象$tokenObject 包含token_type,expires_in,refresh_expires_in,access_token,refresh_token

$user = Users::first();
$tokenObject = Auth::login($user);//$user可以是对象 同样可以是数组
    
    
// 默认为user角色 当你是admin登入时
$admin = Admin::first();
$tokenObject = Auth::guard('admin')->login($admin);

```

5.获取当前登入用户信息

```

 $user = Auth::user(); //得到用户模型对象，查库数据，需查询动态数据时使用
 $user = Auth::user(true); // 得到扩展数据对象，非查库数据,比如只需得到用户ID或不常更新字段使用
 $admin = Auth::guard('admin')->user(); //当前登入管理员
 
```

6.退出登入

```

 $logout = Auth::logout(); //退出当前用户
 $logout = Auth::logout(true); // 退出所有当前用户终端
 $logout = Auth::guard('admin')->logout(); //管理员退出
 
```

7.刷新当前登入用户token

```

 $refresh = Auth::refresh();
 $refresh = Auth::guard('admin')->refresh(); //管理员刷新
 
```

8.单独设置过期时间

```

Auth::accessTime(3600)->refreshTime(360000)->login($user);
Auth::accessTime(3600)->refreshTime(360000)->attempt(['name'= 'tycoonSong','password' = '123456']);
Auth::accessTime(3600)->refresh();

```

9.获取报错信息 Auth::fail();

```
    //默认设定是不会报错的 
    $user = Auth::user(); //当没有登入或异常时返回的null 用于用户可登入或可不登入场景里 只需要判断 $user == null 即可
    //而比如在会员中心调用时 
    $user = Auth::fail()->user(); //走的是异常处理类https://www.workerman.net/doc/webman/exception.html
```

10.开启redis后,建议开启

```
    // 在使用过程中我们通常一个接口允许多端使用的情况 那么默认设置是不限制使用端口的 
    // 可当你想允许比如web端同一账号只允许存在三个终端在线或同一账号APP只允许一个终端使用
    // 默认为web终端 传参client_type=web或你其它的终端client_type=ios
    //config/plugin/shopwwi/auth/app.php设置
    'guard' => [
         'user' => [
             'key' => 'id',
             'field' => ['id','name','email','mobile'], //设置允许写入扩展中的字段
             'num' => -1, // -1为不限制终端在线数量 0为只允许登入一个设备 大于0为每个终端同时在线数量 建议设置为1 则每个终端在线1个
             'model'=> Shopwwi\B2b2c\Models\Users::class
         ]
     ],
     
    Auth::logout(true); // 退出所有当前用户终端
    
```

11.直接调用jwt

```
//本来是打算直接用tinywan/jwt的 可是跟我的业务逻辑不太匹配 因此改造了一些
    use Shopwwi\WebmanAuth\Facade\JWT as JwtFace;
    JwtFace::make(array $extend,int $access_exp = 0,int $refresh_exp = 0); //生成token
    JwtFace::refresh(int $accessTime = 0); //刷新令牌
    JwtFace::verify($token); //验证令牌
```