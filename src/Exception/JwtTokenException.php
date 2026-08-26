<?php
/**
 *-------------------------------------------------------------------------s*
 *
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


namespace Shopwwi\WebmanAuth\Exception;


class JwtTokenException extends \RuntimeException
{
    protected $error;

    public function __construct($error,$code = 401)
    {
        parent::__construct();
        $this->error = $error;
        $this->code = $code;
        $this->message = is_array($error) ? implode(PHP_EOL, $error) : $error;
    }

    /**
     * @param mixed $code
     * @return JwtTokenException
     */
    public function setCode($code): JwtTokenException
    {
        $this->code = $code;
        return $this;
    }

    /**
     * 获取验证错误信息
     * @access public
     * @return array|string
     */
    public function getError()
    {
        return $this->error;
    }
}