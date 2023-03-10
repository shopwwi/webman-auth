<?php
/**
 *-------------------------------------------------------------------------p*
 *
 *-------------------------------------------------------------------------h*
 * @copyright  Copyright (c) 2015-2022 Shopwwi Inc. (http://www.shopwwi.com)
 *-------------------------------------------------------------------------c*
 * @license    http://www.shopwwi.com        s h o p w w i . c o m
 *-------------------------------------------------------------------------e*
 * @link       http://www.shopwwi.com by 象讯科技 phcent.com
 *-------------------------------------------------------------------------n*
 * @since      shopwwi象讯·PHP商城系统Pro
 *-------------------------------------------------------------------------t*
 */


namespace Shopwwi\WebmanAuth;


use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT as jwtMan;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Shopwwi\WebmanAuth\Exception\JwtTokenException;
use Shopwwi\WebmanAuth\Facade\Str;
use support\Redis;
use UnexpectedValueException;

class JWT
{
    /**
     *  access_token. refresh_token.
     */
    const REFRESH = 2, ACCESS = 1;

    /**
     * 自动报错
     * @var bool
     */
    protected $guard = 'user';
    protected $config = [];
    protected $redis = false;

    /**
     * 构造方法
     * @access public
     */
    public function __construct()
    {
        $_config = config('plugin.shopwwi.auth.app.jwt');
        if (empty($_config)) {
            throw new JwtTokenException('The configuration file is abnormal or does not exist');
        }
        $this->config = $_config;
        if ($_config['redis']) {

            $this->redis = true;
        }

    }

    /**
     * 设置角色
     * @param string $guard
     * @return $this
     */
    public function guard($guard = 'user')
    {
        $this->guard = $guard;
        return $this;
    }

    /**
     * 生成令牌
     * @param array $extend
     * @param int $access_exp
     * @param int $refresh_exp
     * @return mixed
     */
    public function make(array $extend, int $access_exp = 0, int $refresh_exp = 0)
    {
        $exp = $access_exp > 0 ? $access_exp : $this->config['access_exp'];
        $refreshExp = $refresh_exp > 0 ? $refresh_exp : $this->config['refresh_exp'];
        $payload = self::payload($extend, $exp, $refreshExp);
        $secretKey = self::getPrivateKey();
        $accessToken = self::makeToken($payload['accessPayload'], $secretKey, $this->config['algorithms']);

        $refreshSecretKey = self::getPrivateKey(self::REFRESH);
        $refreshToken = self::makeToken($payload['refreshPayload'], $refreshSecretKey, $this->config['algorithms']);

        //获取主键
        $idKey = config("plugin.shopwwi.auth.app.guard.{$this->guard}.key");
        //redis 开启
        if ($this->redis) {
            $this->setRedis($extend[$idKey], $accessToken, $refreshToken, $exp, $refreshExp);
            //存储session
            session()->set("token_{$this->guard}", $accessToken);
        } else {
            //存储session
            session()->set("token_{$this->guard}", $accessToken);
        }
        return json_decode(json_encode([
            'token_type' => 'Bearer',
            'expires_in' => $exp,
            'refresh_expires_in' => $refreshExp,
            'access_token' => $accessToken,
            'refresh_token' => $refreshToken,
        ]));
    }

    /**
     * 刷新token值
     * @return object
     */
    public function refresh(int $accessTime = 0): ?object
    {
        $token = $this->getTokenFormHeader();
        $tokenPayload = (array)self::verifyToken($token, self::REFRESH);
        $tokenPayload['exp'] = time() + ($accessTime > 0 ? $accessTime : $this->config['access_exp']);
        $secretKey = $this->getPrivateKey();
        $newToken = $this->makeToken($tokenPayload, $secretKey, $this->config['algorithms']);
        $tokenObj = json_decode(json_encode(['access_token' => $newToken]));
        if ($this->redis) {
            //获取主键
            $idKey = config("plugin.shopwwi.auth.app.guard.{$this->guard}.key");
            $this->setRedis($tokenPayload['extend']->$idKey, $tokenObj->access_token, $token, $this->config['access_exp'], $this->config['refresh_exp']);
        }
        return $tokenObj;
    }

    /**
     * 获取token信息
     * @return mixed|string|null
     */
    protected function getTokenFormHeader()
    {
        $header = request()->header('Authorization', '');
        $token = request()->input('_token');
        if (Str::startsWith($header, 'Bearer ')) {
            $token = Str::substr($header, 7);
        }
        if (!empty($token) && Str::startsWith($token, 'Bearer ')) {
            $token = Str::substr($token, 7);
        }
        $token = $token ?? session("token_{$this->guard}", null);
        if (empty($token)) {
            $token = null;
            $fail = new JwtTokenException('尝试获取的Authorization信息不存在');
            $fail->setCode(401);
            throw $fail;
        }
        return $token;
    }

    /**
     * @desc: 验证令牌
     * @param string|null $token
     * @param int $tokenType
     * @return object
     * @throws JwtTokenException
     */
    public function verify(string $token = null, int $tokenType = self::ACCESS): ?object
    {
        $token = $token ?? $this->getTokenFormHeader();
        return $this->verifyToken($token, $tokenType);
    }

    /**
     * 验证token值
     * @param string $token
     * @param int $tokenType
     * @return object
     */
    public function verifyToken(string $token, int $tokenType): ?object
    {
        $secretKey = self::ACCESS == $tokenType ? $this->getPublicKey($this->config['algorithms']) : $this->getPublicKey($this->config['algorithms'], self::REFRESH);
        jwtMan::$leeway = 60;
        try {
            // v5.5.1 return (array) JWT::decode($token, $secretKey, [$this->config['algorithms']]);
            $tokenPayload = jwtMan::decode($token, new Key($secretKey, $this->config['algorithms']));
            if ($tokenPayload->guard != $this->guard) {
                throw new SignatureInvalidException('无效令牌');
            }
            //redis 开启
            if ($this->redis) {
                //获取主键
                $idKey = config("plugin.shopwwi.auth.app.guard.{$this->guard}.key");
                $this->checkRedis($tokenPayload->extend->$idKey, $token, $tokenType);
            }
            return $tokenPayload;
        } catch (SignatureInvalidException $e) {
            throw new JwtTokenException('身份验证令牌无效', 401);
        } catch (BeforeValidException $e) { // 签名在某个时间点之后才能用
            throw new JwtTokenException('身份验证令牌尚未生效', 403);
        } catch (ExpiredException $e) { // token过期
            throw new JwtTokenException('身份验证会话已过期，请重新登录！', 402);
        } catch (UnexpectedValueException $unexpectedValueException) {
            throw new JwtTokenException('获取扩展字段不正确', 401);
        } catch (\Exception $exception) {
            throw new JwtTokenException($exception->getMessage(), 401);
        }

    }

    /**
     * 获取扩展字段.
     * @param string|null $token
     * @param int $tokenType
     * @return object
     * @throws JwtTokenException
     */
    public function getTokenExtend(string $token = null, int $tokenType = self::ACCESS): ?object
    {
        return $this->verify($token, $tokenType);
    }

    /**
     * 生成token值
     * @param array $payload
     * @param string $secretKey
     * @param string $algorithms
     * @return string
     */
    public function makeToken(array $payload, string $secretKey, string $algorithms): string
    {
        try {
            return jwtMan::encode($payload, $secretKey, $algorithms);
        } catch (ExpiredException $e) { //签名不正确
            throw new JwtTokenException('签名不正确', 401);
        } catch (\Exception $e) { //其他错误
            throw new JwtTokenException('其它错误', 401);
        }
    }

    /**
     * 获取加载体
     * @param array $extend
     * @param int $access_exp
     * @param int $refresh_exp
     * @return array
     */
    public function payload(array $extend, int $access_exp = 0, int $refresh_exp = 0): array
    {
        $basePayload = [
            'iss' => $this->config['iss'],
            'iat' => time(),
            'exp' => time() + $access_exp,
            'extend' => $extend,
            'guard' => $this->guard
        ];
        $resPayLoad['accessPayload'] = $basePayload;
        $basePayload['exp'] = time() + $refresh_exp;
        $resPayLoad['refreshPayload'] = $basePayload;
        return $resPayLoad;
    }

    /**
     * 根据签名算法获取【公钥】签名值
     * @param string $algorithm
     * @param int $tokenType
     * @return string
     */
    protected function getPublicKey(string $algorithm, int $tokenType = self::ACCESS): string
    {
        switch ($algorithm) {
            case 'HS256':
                $key = self::ACCESS == $tokenType ? $this->config['access_secret_key'] : $this->config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS == $tokenType ? $this->config['access_public_key'] : $this->config['refresh_public_key'];
                break;
            default:
                $key = $this->config['access_secret_key'];
        }
        return $key;
    }

    /**
     * 根据签名算法获取【私钥】签名值
     * @param int $tokenType
     * @return mixed
     */
    protected function getPrivateKey(int $tokenType = self::ACCESS): string
    {
        switch ($this->config['algorithms']) {
            case 'HS256':
                $key = self::ACCESS == $tokenType ? $this->config['access_secret_key'] : $this->config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS == $tokenType ? $this->config['access_private_key'] : $this->config['refresh_private_key'];
                break;
            default:
                $key = $this->config['access_secret_key'];
        }

        return $key;
    }

    /**
     * 退出登入
     */
    public function logout($all = false)
    {
        $token = $this->getTokenFormHeader();
        $tokenPayload = self::verifyToken($token, self::ACCESS);
        //redis 开启
        if (isset($this->config['redis']) && $this->config['redis']) {

            //获取主键
            $idKey = config("plugin.shopwwi.auth.app.guard.{$this->guard}.key");
            $id = $tokenPayload->extend->$idKey;
            if ($all) {
                Redis::hDel("token_{$this->guard}", $id);
            } else {
                $list = Redis::hGet("token_{$this->guard}", $id);
                if ($list) {
                    $tokenList = unserialize($list);
                    foreach ($tokenList as $key => $val) {
                        if ($val['accessToken'] == $token) {
                            unset($tokenList[$key]);
                        }
                    }
                    if (count($tokenList) == 0) {
                        Redis::hDel("token_{$this->guard}", $id);
                    } else {
                        Redis::hSet("token_{$this->guard}", $id, serialize($tokenList));
                    }
                }
            }

        }
        //清理session数据
        session()->forget("token_{$this->guard}");
    }

    /**
     * 写入redis
     * @param int $id
     * @param $accessToken
     * @param $refreshToken
     * @param $accessExp
     * @param $refreshExp
     */
    protected function setRedis(int $id, $accessToken, $refreshToken, $accessExp, $refreshExp)
    {
        $list = Redis::hGet("token_{$this->guard}", $id);
        $clientType = strtolower(request()->input('client_type', 'web'));
        $defaultList = [
            'accessToken' => $accessToken,
            'refreshToken' => $refreshToken,
            'clientType' => $clientType,
            'accessExp' => $accessExp,
            'refreshExp' => $refreshExp,
            'refreshTime' => time(),
            'accessTime' => time(),
        ];
        if ($list != null) {
            $tokenList = unserialize($list);
            $maxNum = config("plugin.shopwwi.auth.app.guard.{$this->guard}.num");
            if (is_array($tokenList)) {
                if ($maxNum === -1) { //不限制
                    $match = false;
                    foreach ($tokenList as &$item) {
                        if ($item['refreshToken'] === $refreshToken) {
                            $match = true;
                            $item['accessToken'] = $accessToken;
                            $item['accessExp'] = $accessExp;
                            $item['accessTime'] = $defaultList['accessTime'];
                            break;
                        }
                    }
                    !$match && $tokenList[] = $defaultList;
                    Redis::hSet("token_{$this->guard}", $id, serialize($tokenList));
                } elseif ($maxNum === 0) { // 只允许一个终端
                    Redis::hSet("token_{$this->guard}", $id, serialize([$defaultList]));
                } elseif ($maxNum > 0) { // 限制同一终端使用个数
                    $clientTypeNum = 0;
                    $index = -1;
                    foreach ($tokenList as $key => $val) {
                        if ($val['clientType'] == $clientType) {
                            $clientTypeNum++;
                            $index < 0 && $index = $key;
                        }
                    }
                    if ($index >= 0 && $clientTypeNum >= $maxNum) {
                        unset($tokenList[$index]);
                    }
                    $match = false;
                    foreach ($tokenList as &$item) {
                        if ($item['refreshToken'] === $refreshToken) {
                            $match = true;
                            $item['accessToken'] = $accessToken;
                            $item['accessExp'] = $accessExp;
                            $item['accessTime'] = $defaultList['accessTime'];
                            break;
                        }
                    }
                    !$match && $tokenList[] = $defaultList;
                    Redis::hSet("token_{$this->guard}", $id, serialize($tokenList));
                }
                //清理过期token
                $this->clearExpRedis($id);
            }
        } else {
            Redis::hSet("token_{$this->guard}", $id, serialize([$defaultList]));
        }
    }

    /**
     * 清理过期token
     * @param int $id
     */
    public function clearExpRedis(int $id)
    {
        $list = Redis::hGet("token_{$this->guard}", $id);
        if ($list) {
            $tokenList = unserialize($list);
            $refresh = false;
            foreach ($tokenList as $key => $val) {
                if (($val['refreshTime'] + $val['refreshExp']) < time()) {
                    unset($tokenList[$key]);
                    $refresh = true;
                }
            }
            if (count($tokenList) == 0) {
                Redis::hDel("token_{$this->guard}", $id);
            } else {
                if ($refresh) {
                    Redis::hSet("token_{$this->guard}", $id, serialize($tokenList));
                }
            }
        }
    }

    /**
     * 验证token是否存在
     * @param int $id
     * @param string $token
     * @param int $tokenType
     */
    public function checkRedis(int $id, string $token, int $tokenType = self::ACCESS)
    {
        $list = Redis::hGet("token_{$this->guard}", $id);
        if ($list != null) {
            $tokenList = unserialize($list);
            $checkToken = false;
            $expireToken = false;
            foreach ($tokenList as $key => $val) {
                if ($tokenType == self::REFRESH && $val['refreshToken'] == $token) {
                    if (\bcadd($val['refreshTime'], $val['refreshExp'], 0) < time()) {
                        unset($tokenList[$key]);
                    } else {
                        $checkToken = true;
                    }
                }
                if ($tokenType == self::ACCESS && $val['accessToken'] == $token) {
                    if (\bcadd($val['accessTime'], $val['accessExp'], 0) < time()) {
                        $expireToken = true;
                    } else {
                        $checkToken = true;
                    }
                }
            }
            if (count($tokenList) == 0) {
                Redis::hDel("token_{$this->guard}", $id);
            } else {
                Redis::hSet("token_{$this->guard}", $id, serialize($tokenList));
            }
            if (!$checkToken) {
                if ($expireToken) {
                    throw new ExpiredException('无效');
                } else {
                    throw new SignatureInvalidException('无效');
                }
            }
        } else {
            throw new SignatureInvalidException('无效');
        }
    }

    /**
     * 动态方法 直接调用is方法进行验证
     * @access public
     * @param string $method 方法名
     * @param array $args 调用参数
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
