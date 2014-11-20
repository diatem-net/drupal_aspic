<?php

use jin\lang\ListTools;

class SecureCookie {
    
    private static $hashMethod = 'md5';
    private static $encodeMethod = 'aes128';
    private static $initializationVector = '1234567812345678';

    public static function setHashMethod($method){
	self::$hashMethod = $method;
    }
    
    public static function setEncodeMethod($method){
	self::$encodeMethod = $method;
    }
    
    public static function setInitializationVector($vector){
	self::$initializationVector = $vector;
    }
    
    public static function delete($cookiename){
	setcookie($cookiename, '', time()-3600);
    }
    
    
    public static function cookieExists($cookiename) {
	return (isset($_COOKIE[$cookiename]));
    }

    
    public static function setSecureCookie($serviceId, $cookiename, $value, $privateKey, $expire = 0, $path = '', $domain= '', $secure = false, $httponly = null){
	$json = json_encode($value);
	$securedValue = openssl_encrypt($json, self::$encodeMethod, $privateKey, false, self::$initializationVector);

	$controlString = $serviceId.'|'.$expire.'|'.$securedValue.'|'.md5($_SERVER['HTTP_USER_AGENT']);
	$controlString = hash(self::$hashMethod, $controlString);
	
	self::setUnsecureCookie($cookiename, $securedValue.'|'.$controlString, $expire, $path, $domain, $secure, $httponly);
    }
    
    /**
     * Send a classic (unsecure) cookie
     *
     * @param string $name cookie name
     * @param string $value cookie value
     * @param integer $expire expiration time
     * @param string $path cookie path
     * @param string $domain cookie domain
     * @param bool $secure when TRUE, send the cookie only on a secure connection
     * @param bool $httponly when TRUE the cookie will be made accessible only through the HTTP protocol
     */
    public static function setUnsecureCookie($cookiename, $value, $expire = 0, $path = '', $domain = '', $secure = false, $httponly = null) {
	/* httponly option is only available for PHP version >= 5.2 */
	if ($httponly === null) {
	    setcookie($cookiename, $value, $expire, $path, $domain, $secure);
	} else {
	    setcookie($cookiename, $value, $expire, $path, $domain, $secure, $httponly);
	}
    }
    
    public static function getSecureCookie($cookiename, $serviceId, $privateKey, $md5UserAgent = null, $expire = 0){
	if(!isset($_COOKIE[$cookiename])){
	    return false;
	}
	
	$cookieValue = $_COOKIE[$cookiename];
	$encoded = self::ListGetAt($cookieValue, 0, '|');
	$control = self::ListGetAt($cookieValue, 1, '|');
	
	if(!$md5UserAgent){
	    $md5UserAgent = md5($_SERVER['HTTP_USER_AGENT']);
	}
	
	$controlString = hash(self::$hashMethod, $serviceId.'|'.$expire.'|'.$encoded.'|'.$md5UserAgent);
	if($controlString != $control){
	    return false;
	}
	
	$decrypted = openssl_decrypt($encoded, self::$encodeMethod, $privateKey, false, self::$initializationVector);
	return json_decode($decrypted);
    }
    
    public static function ListGetAt($list, $index, $delimiter = ','){
	$arr = self::toArray($list, $delimiter);
	return $arr[$index];
    }
    
    /**
     * Convertit une liste en tableau
     * @param string $list  Liste source
     * @param string $delimiter	Séparateur
     * @return string
     */
    public static function toArray($list, $delimiter = ','){
	if($list == ''){
	    return array();
	}else{
	    return self::explode($list, $delimiter);
	}
	
    }
    
    /** Coupe la chaîne en un tableau
     *
     *  @param  string  $chaine                 Chaîne de caractères
     *  @param  string  $delimiter              [optionel] Caractère ou chaîne utilisée pour découper le tableau. (Si la chaîne est vide ou non fournie la chaîne sera découpée pour chaque caractère)
     *  @return array                       Tableau de chaînes de caractères
     */
    public static function explode($chaine, $delimiter = '') {
        if ($delimiter == '') {
            return str_split($chaine);
        } else {
            return explode($delimiter, $chaine);
        }
    }

}
