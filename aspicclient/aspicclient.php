<?php

include 'securecookie.php';
include 'curl.php';

class AspicClient{
    private static $initialized = false;
    private static $serverDataGetted = false;
    private static $host;
    private static $ssl;
    private static $serviceId;
    private static $privateKey;
    private static $encryptMethod;
    private static $initializationVector;
    private static $groups;
    private static $userData;
    private static $userId;
    
    private static $cookieName;
    private static $serverLoginUrl;
    
    public static function init($host, $serviceId, $privateKey, $ssl = true, $encryptMethod = 'aes128', $initializationVector = '1234567812345678'){
	self::$host = $host;
	self::$ssl = $ssl;
	self::$serviceId = $serviceId;
	self::$privateKey = $privateKey;
	self::$encryptMethod = $encryptMethod;
	self::$initializationVector = $initializationVector;
	
	self::$initialized = true;
	
	self::checkReturn();
    }
    
    public static function isAuthentified(){
	return self::getAuthDataFromServer();
    }
    
    public static function login(){
	if(!self::isAuthentified()){
	    header('Location:'.self::getLoginServerUrl());   
	}
    }
    
    public static function logout(){
	SecureCookie::delete(self::getCookieName());
	header('Location:'.self::getLoginServerUrl().'&logout=1');   
    }
    
    public static function getUserId(){
	self::getAuthDataFromServer();
	return self::$userId;
    }
    
    public static function getUserData(){
	self::getAuthDataFromServer();
	return self::$userData;
    }
    
    public static function getUserGroups(){
	self::getAuthDataFromServer();
	return self::$groups;
    }
    
    private static function checkReturn(){
	if(isset($_REQUEST['s']) && isset($_REQUEST['sid'])){
	    if($_REQUEST['sid'] != self::$serviceId){
		return;
	    }
	    
	    $secured = $_REQUEST['s'];
	    $unsecured = openssl_decrypt($secured, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);
	    $data = json_decode($unsecured, true);
	   
	    
	    SecureCookie::setSecureCookie(self::$serviceId, self::getCookieName(), $data['uid'], self::$privateKey, 0, '', '', false, null);
	    
	    header('Location: '.self::getCurrentUrlWithoutArgs());
	}
    }
    
    private static function getAuthDataFromServer() {
	if (!self::$serverDataGetted) {
	    if (SecureCookie::cookieExists(self::getCookieName())) {
		$uid = SecureCookie::getSecureCookie(self::getCookieName(), self::$serviceId, self::$privateKey, md5($_SERVER['HTTP_USER_AGENT']), 0);

		if (!$uid) {
		    return false;
		}

		$args = array(
		    'uid' => $uid,
		    'url' => self::getCurrentUrl(),
		    'serviceId' => self::$serviceId
		);
		$secureString = $uid . '|' . self::getCurrentUrl() . '|' . md5($_SERVER['HTTP_USER_AGENT']);
		$secured = openssl_encrypt($secureString, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);
		$results = Curl::call(self::getBaseServerUrl(), array('sid' => self::$serviceId, 's' => $secured), 'POST', true);
		
		if (Curl::getLastHttpCode() != 200) {
		    return false;
		}
		

		$decryptedResults = openssl_decrypt($results, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);
		
		
		
		if (!$decryptedResults) {
		    return false;
		}

		$decryptedResults = json_decode($decryptedResults, true);
		if (!$decryptedResults) {
		    return false;
		}
		
		self::$groups = $decryptedResults['groups'];
		self::$userData = $decryptedResults['userData'];
		self::$userId = $decryptedResults['userId'];

		self::$serverDataGetted = true;
		
		return true;
	    } else {
		return false;
	    }
	}else{
	    return false;
	}
    }

    private static function getCookieName(){
	if(self::$cookieName){
	    return self::$cookieName;
	}
	
	self::$cookieName = md5(self::$serviceId);
	return self::$cookieName;
    }
    
    private static function getLoginServerUrl(){
	if(self::$serverLoginUrl){
	    return self::$serverLoginUrl;
	}
	
	$url = self::getBaseServerUrl();
	
	$secureString = self::$serviceId.'|'.self::getCurrentUrl().'|'.md5($_SERVER['HTTP_USER_AGENT']);
	$secured = openssl_encrypt($secureString, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);

	$url .= '?sid='.self::$serviceId.'&s='.urlencode($secured);
	
	self::$serverLoginUrl = $url;
	
	return $url;
    }
    
    private static function getBaseServerUrl(){
	$url = 'http';
	if(self::$ssl){
	    $url .= 's';
	}
	$url .= '://'.self::$host;
	
	return $url;
    }
    
    private static function getCurrentUrl(){

	$pageURL = 'http';
	if (isset($_SERVER['https']) && $_SERVER["HTTPS"] == "on") {
	    $pageURL .= "s";
	}
	$pageURL .= "://";
	$pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];
	
	return $pageURL;
    }
    
    private static function getCurrentUrlWithoutArgs(){

	$currentArgs = $_GET;
	$currentUrl = self::getCurrentUrl();
	
	$currentUrlSeg = explode('?', $currentUrl);
	$currentUrl = $currentUrlSeg[0];
	
	$first = true;
	foreach ($currentArgs as $k => $v){
	    if($k != 's' && $k != 'sid'){
		if($first){
		    $currentUrl .= '?'.$k.'='.$v;
		    $first = false;
		}else{
		    $currentUrl .= '&'.$k.'='.$v;
		}
	    }
	}
	
	return $currentUrl;
    }

}
