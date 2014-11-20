<?php


/** Classe permettant de gérer des appels CURL
 */
class Curl {

    /**
     *
     * @var string  Dernière erreur rencontrée
     */
    private static $lastErrorText = '';
    
    /**
     *
     * @var int	Dernier code d'erreur rencontré
     */
    private static $lastErrorCode = 0;

    
    private static $lastCurlInfo;
    
    /**
     * Appelle une Url
     * @param type $url		Url à appeler
     * @param type $args	[optional] Arguments à transmettre en POST (NULL par défaut)
     * @param type $requestType	[optionel] Type de requête. (POST,GET, DELETE ou PUT) (POST par défaut)
     * @param type $throwError	[optionel] Génère les erreurs directement (True par défaut)
     * @return boolean
     * @throws \Exception
     */
    public static function call($url, $args = null, $requestType = 'POST', $throwError = true){
	$curl = curl_init();
	curl_setopt($curl, CURLOPT_URL, $url);
	curl_setopt($curl, CURLOPT_COOKIESESSION, true);
	curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
	
	
	if ($requestType == 'DELETE') {
	    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
	    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($args));
	}

	if ($requestType == 'GET') {
	    if(!self::contains($url, '?')){
		$url .= '?' . http_build_query($args);
	    }else{
		$url .= '?' . http_build_query($args);
	    }
	    
	}

	if($requestType == 'POST') {
	    curl_setopt($curl, CURLOPT_POST, TRUE);
	    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($args));
	}

	if ($requestType == 'PUT') {
	    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
	    curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($args));
	}


	$return = curl_exec($curl);
	self::$lastCurlInfo = curl_getinfo($curl);
	
	if (!$return) {
	    $errornum = curl_errno($curl);
	    $errortxt = 'Impossible d\'appeler l\'url : ' . $url . ' : (ERREUR CURL ' . $errornum . ') ' . curl_error($curl);
	    if ($throwError) {
		throw new \Exception($errortxt);
	    }
	    self::$lastErrorText = $errortxt;
	    self::$lastErrorCode = $errornum;


	    return false;
	}
	curl_close($curl);

	return $return;
    }

    
    /**
     * Retourne le dernier code d'erreur rencontré
     * @return int
     */
    public static function getLastErrorCode() {
	return self::$lastErrorCode;
    }

    
    /**
     * Retourne la dernière erreur rencontrée (verbose)
     * @return string
     */
    public static function getLastErrorVerbose() {
	return self::$lastErrorText;
    }
    
    public static function getLastHttpCode(){
	if(isset(self::$lastCurlInfo['http_code'])){
	    return self::$lastCurlInfo['http_code'];
	}else{
	    return false;
	}
    }
    
    
    public static function getLastHttpCodeVerbose(){
	if(isset(self::$lastCurlInfo['http_code'])){
	    $status = array(
	    100 => 'Continue',
	    101 => 'Switching Protocols',
	    200 => 'OK',
	    201 => 'Created',
	    202 => 'Accepted',
	    203 => 'Non-Authoritative Information',
	    204 => 'No Content',
	    205 => 'Reset Content',
	    206 => 'Partial Content',
	    300 => 'Multiple Choices',
	    301 => 'Moved Permanently',
	    302 => 'Found',
	    303 => 'See Other',
	    304 => 'Not Modified',
	    305 => 'Use Proxy',
	    306 => '(Unused)',
	    307 => 'Temporary Redirect',
	    400 => 'Bad Request',
	    401 => 'Unauthorized',
	    402 => 'Payment Required',
	    403 => 'Forbidden',
	    404 => 'Not Found',
	    405 => 'Method Not Allowed',
	    406 => 'Not Acceptable',
	    407 => 'Proxy Authentication Required',
	    408 => 'Request Timeout',
	    409 => 'Conflict',
	    410 => 'Gone',
	    411 => 'Length Required',
	    412 => 'Precondition Failed',
	    413 => 'Request Entity Too Large',
	    414 => 'Request-URI Too Long',
	    415 => 'Unsupported Media Type',
	    416 => 'Requested Range Not Satisfiable',
	    417 => 'Expectation Failed',
	    500 => 'Internal Server Error',
	    501 => 'Not Implemented',
	    502 => 'Bad Gateway',
	    503 => 'Service Unavailable',
	    504 => 'Gateway Timeout',
	    505 => 'HTTP Version Not Supported');
	    return ($status[self::$lastCurlInfo['http_code']]) ? $status[self::$lastCurlInfo['http_code']] : $status[500];
	}else{
	    return false;
	}
    }
    
    public static function contains($chaine, $recherche, $nocase = false) {
        if (self::firstIndexOf($chaine, $recherche, $nocase) == -1)
            return false;
        return true;
    }
    
    /** Cherche la première occurence d'une sous-chaîne dans la chaîne en commençant à l'index spécifié. Retourne -1 si aucune occurence n'est trouvée
     *
     *  @param  string  $chaine                 Chaîne de caractères
     *  @param  string  $recherche              Chaîne à rechercher
     *  @param  boolean $nocase                 [optionel] Ne pas prendre en compte la casse (FALSE par défaut)
     *  @param  integer $startIndex             [optionel] Index à partir duquel commencer la recherche (0 par défaut)
     *  @return integer                     Position de la chaîne recherchée, -1 si aucune occurence n'est trouvée
     */
    public static function firstIndexOf($chaine, $recherche, $nocase = false, $startIndex = 0) {
        if ($nocase) {
            $f = stripos($chaine, $recherche, $startIndex);
        } else {
            $f = strpos($chaine, $recherche, $startIndex);
        }

        if ($f === false) {
            return -1;
        } else {
            return $f;
        }
    }

}
