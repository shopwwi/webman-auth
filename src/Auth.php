<?php
/**
 *-------------------------------------------------------------------------s*
 * 用户信息自动维护
 *-------------------------------------------------------------------------h*
 * @copyright  Copyright (c) 2025-2099 Shopwwi Inc. (http://www.shopwwi.com)
 *-------------------------------------------------------------------------o*
 * @license    http://www.shopwwi.com        s h o p w w i . c o m
 *-------------------------------------------------------------------------p*
 * @link       http://www.shopwwi.com 
 *-------------------------------------------------------------------------w*
 * @since      shopwwi
 *-------------------------------------------------------------------------w*
 */

namespace Shopwwi\WebmanAuth;

use Shopwwi\WebmanAuth\Exception\JwtTokenException;
use Shopwwi\WebmanAuth\Facade\JWT as JwtFace;
use Shopwwi\WebmanAuth\Facade\Str;

class Auth
{
    /**
     * 未携带 token 报错
     * @var bool
     */
    protected $fail = false;
    /**
     * 自定义角色
     * @var string
     */
    protected $guard = 'user';
    /**
     * 配置信息
     * @var array|mixed
     */
    protected $config = [];

    /**
     * token过期时间
     * @var int
     */
    protected $accessTime = 0;
    protected $refreshTime = 0;

    /**
     * 构造方法
     * @access public
     */
    public function __construct()
    {
        $_config = config('plugin.shopwwi.auth.app');
        if (empty($_config)) {
            throw new JwtTokenException('The configuration file is abnormal or does not exist');
        }
        $this->config = $_config;
    }

    /**
     * 设置当前角色
     * @param string $name
     * @return $this
     */
    public function guard(string $name):Auth
    {
        $this->guard = $name;
        return $this;
    }

    public function isThinkOrm()
    {
        $database = config('database');
        if (isset($database['default']) && strpos($database['default'], 'plugin.') === 0) {
            $database = false;
        }
        $thinkorm = config('thinkorm');
        if (isset($thinkorm['default']) && strpos($thinkorm['default'], 'plugin.') === 0) {
            $thinkorm = false;
        }
        return !$database && $thinkorm;
    }

    /**
     * 单独设定token过期时间
     * @param int $num
     * @return $this
     */
    public function accessTime(int $num): Auth
    {
        $this->accessTime = $num;
        return $this;
    }

    /**
     * 单独设定刷新token过期时间
     * @param int $num
     * @return $this
     */
    public function refreshTime(int $num): Auth
    {
        $this->refreshTime = $num;
        return $this;
    }


    /**
     * 输出报错
     * @param bool $error
     * @return Auth
     */
    public function fail(bool $error = true): Auth
    {
        $this->fail = $error;
        return $this;
    }

    /**
     * 登入信息自动验证
     * @param array $data
     * @return false|mixed
     */
    public function attempt(array $data)
    {
        try {
            if(is_array($data)) {
                list($model,$orm) = $this->getUserClass();
                if($model == null) throw new JwtTokenException('模型不存在',400);
                foreach ($data as $key=>$val){
                    if($key !== 'password'){
                        $model = $model->where($key,$val);
                    }
                }

                if($orm == 'thinkphp'){
                    $model = $model->find();
                }else{
                    $model = $model->first();
                }

                if($model != null){
                    if(isset($data['password'])){
                        if(!password_verify($data['password'],$model->password)){
                            throw new JwtTokenException('密码错误',400);
                        }
                    }
                    return  $this->login($model);
                }
                throw new JwtTokenException('账号或密码错误',400);
            }
            throw new JwtTokenException('数据类型不正确',400);
        }catch (JwtTokenException $e){
            if($this->fail){
                throw new JwtTokenException($e->getMessage(),$e->getCode());
            }
            return false;
        }
    }

    /**
     * 获取用户模型
     * @return mixed|null
     */
    protected function getUserClass(){
        $guardConfig = $this->config['guard'][$this->guard]['model'];
        $orm = 'laravel';
        $class = null;
        if(!empty($guardConfig)){
            if(is_array($guardConfig)){
                $orm = $guardConfig[1];
                $class = $guardConfig[0];
            }else{
                $class = $guardConfig;
            }
        }
        return [new $class,$orm];
    }

    /**
     * 获取会员信息
     * @return mixed|null
     */
    public function user($cache = false)
    {
        try {
            $key = $this->config['guard'][$this->guard]['key']; //获取主键
            $extend = JwtFace::guard($this->guard)->getTokenExtend();
            if(isset($extend->extend) && !empty($extend->extend) && isset($extend->extend->$key)){
                if($cache){
                    return $extend->extend;
                }else{
                    list($model,$orm) = $this->getUserClass();
                    if($orm == 'thinkphp'){
                        return $model->where($key,$extend->extend->$key)->find();
                    }else{
                        return $model->where($key,$extend->extend->$key)->first();
                    }
                }

            }
            throw new JwtTokenException('配置信息异常',401);
        }catch (JwtTokenException $e){
            if($this->fail){
                throw new JwtTokenException($e->getMessage(),$e->getCode());
            }
            return null;
        }
    }

    /**
     * 登入并获取Token
     * @param $data
     */
    public function login($data)
    {
        $fields = $this->config['guard'][$this->guard]['field']; //允许使用的数据
        $idKey = $this->config['guard'][$this->guard]['key']; //获取主键
        $newData = [];
        // 过滤存储数据
        if(is_object($data)){
            foreach ($fields as $key){
                $newData[$key] = $data->$key ?? null;
            }
        }elseif(is_array($data) && count($data) > 0){
            foreach ($fields as $key){
                $newData[$key] = $data[$key] ?? null;
            }
        }

        try {
            if(!isset($newData[$idKey])){
                throw new JwtTokenException('缺少必要主键',400);
            }
            return JwtFace::guard($this->guard)->make($newData,$this->accessTime,$this->refreshTime);
        }catch (JwtTokenException $e){
            if($this->fail){ //当设定自动报错
                throw new JwtTokenException($e->getError(),$e->getCode());
            }
            return null;
        }
    }

    /**
     * 刷新令牌
     * @return false|JWT
     */
    public function refresh()
    {
        try {
            return JwtFace::guard($this->guard)->refresh($this->accessTime);
        }catch (JwtTokenException $e){
            if($this->fail){ //当设定自动报错
                throw new JwtTokenException($e->getError(),$e->getCode());
            }
            return false;
        }
    }

    /**
     * 退出登入
     */
    public function logout($all = false)
    {
        try {
            return JwtFace::guard($this->guard)->logout($all);
        }catch (JwtTokenException $e){
            if($this->fail){ //当设定自动报错
                throw new JwtTokenException($e->getError(),$e->getCode());
            }
            return false;
        }
    }
    /**
     * 生成JWT密钥
     * @return void
     * @throws \Exception
     */
    public function jwtKey()
    {

    }

    /**
     * 加密密码
     * @param $password
     * @return string|null
     */
    public function bcrypt($password): ?string
    {
        $key = config('plugin.shopwwi.auth.app.app_key');
        if (Str::startsWith($key, 'base64:')) {
            $key = base64_decode(substr($key, 7));
        }
        $hash = password_hash($password, PASSWORD_BCRYPT, [
            'cost' => $key,
        ]);

        if ($hash === false) {
            throw new JwtTokenException('Bcrypt hashing not supported.');
        }

        return $hash;
    }

    /**
     * 动态方法 直接调用is方法进行验证
     * @access public
     * @param string $method 方法名
     * @param array $args   调用参数
     * @return bool
     */
    public function __call(string $method, array $args)
    {
        if ('is' == strtolower(substr($method, 0, 2))) {
            $method = substr($method, 2);
        }

        $args[] = lcfirst($method);

        return call_user_func_array([$this, 'is'], $args);
    }

}
