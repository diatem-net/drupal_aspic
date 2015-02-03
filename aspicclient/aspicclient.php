<?php

include 'securecookie.php';
include 'curl.php';

/**
 * Classe de gestion de sessions d'authentification ASPIC
*/
class AspicClient {
    /**
     * Session correctement initialisée ?
     * @var boolean 
     */
    private static $initialized = false;
    
    /**
     * Données du serveur réceptionnées ?
     * @var boolean
     */
    private static $serverDataGetted = false;
    
    /**
     * Url du serveur Aspic
     * @var string
     */
    private static $host;
    
    /**
     * SSL activé ?
     * @var boolean
     */
    private static $ssl;
    
    /**
     * Id du service Aspic
     * @var type 
     */
    private static $serviceId;
    
    /**
     * Clé privée du service ASPIC
     * @var string
     */
    private static $privateKey;
    
    /**
     * Arguments GET ignorés lors des redirections
     * @var array
     */
    private static $ignoredGetArgs;
    
    /**
     * Méthode d'encodage utilisée.
     * @var string
     */
    private static $encryptMethod;
    
    /**
     * Vecteur d'initialisation de l'encodage
     * @var string
     */
    private static $initializationVector;
    
    /**
     * Groupes d'utilisateurs dans lequel l'utilisateur authentifié est.
     * @var array
     */
    private static $groups;
    
    /**
     * Données utilisateur
     * @var array
     */
    private static $userData;
    
    /**
     * Identifiant unique de l'utilisateur connecté
     * @var string
     */
    private static $userId;
    
    /**
     * Données contextuelles à la connexion transmises à/de Aspic
     * @var array
     */
    private static $extraArguments;
    
    /**
     * Nom du cookie
     * @var string
     */
    private static $cookieName;
    
    /**
     * Url d'accès au serveur pour la connexion
     * @var string
     */
    private static $serverLoginUrl;

    
    /**
     * Initialisation d'une sessions ASPIC (Doit toujours être appelé avant toute opération)
     * @param string    $host                   Url du serveur ASPIC
     * @param string    $serviceId              ID du service ASPIC
     * @param string    $privateKey             Clé privée associée au service ASPIC 
     * @param boolean   $ssl                    SSL activé. (Devrait être TRUE pour un environnement en production)
     * @param string    $encryptMethod          Méthode d'encryption des données utilisée. (En fonction de la configuration du serveur ASPIC)
     * @param string    $initializationVector   Chaîne d'initialisation pour l'encodage. (En fonction de la configuration du serveur ASPIC)
     * @param array     $ignoredGetArgs         Arguments GET qui seront ignorés lors des redirections
     */
    public static function init($host, $serviceId, $privateKey, $ssl = true, $encryptMethod = 'aes128', $initializationVector = '1234567812345678', $ignoredGetArgs = array()) {
        self::$host = $host;
        self::$ssl = $ssl;
        self::$serviceId = $serviceId;
        self::$privateKey = $privateKey;
        self::$encryptMethod = $encryptMethod;
        self::$initializationVector = $initializationVector;
        self::$ignoredGetArgs = $ignoredGetArgs;

        self::$initialized = true;

        self::checkReturn();
    }

    
    /**
     * retourne TRUE si l'utilisateur est actuellement authentifié.
     * @return boolean
     */
    public static function isAuthentified() {
        return self::getAuthDataFromServer();
    }

    
    /**
     * Ouvre une nouvelle demande d'authentification auprès d'Aspic
     * @param array $extraArguments Données contextuelles liées à la connexion qui seront transmises à Aspic. (Si activé sur le serveur)
     */
    public static function login($extraArguments = null) {
        if (!self::isAuthentified()) {
            header('Location:' . self::getLoginServerUrl($extraArguments));
        }
    }

    
    /**
     * Ferme la session d'authentification unifiée courante
     */
    public static function logout() {
        SecureCookie::delete(self::getCookieName());
        header('Location:' . self::getLoginServerUrl() . '&logout=1');
    }

    
    /**
     * Retourne l'identifiant unique de l'utilisateur
     * @return string
     */
    public static function getUserId() {
        self::getAuthDataFromServer();
        return self::$userId;
    }

    
    /**
     * Retourne les données de l'utilisateur authentifié. (Si supporté par le serveur)
     * @return array
     */
    public static function getUserData() {
        self::getAuthDataFromServer();
        return self::$userData;
    }

    
    /**
     * Retourne les données contextuelles transmises à/de Aspic. (Si supporté par le serveur)
     * @return array
     */
    public static function getExtraArguments() {
        self::getAuthDataFromServer();
        return self::$extraArguments;
    }

    
    /**
     * Retourne les groupes d'utilisateurs dans lesquels l'utilisateur courant est.
     * @return array
     */
    public static function getUserGroups() {
        self::getAuthDataFromServer();
        return self::$groups;
    }

    
    /**
     * Vérifie si des données retournées par le serveur ASPIC sont transmises, auquel cas on effectue la connexion.
     * @return null
     */
    private static function checkReturn() {
        if (isset($_REQUEST['s']) && isset($_REQUEST['sid'])) {
            if ($_REQUEST['sid'] != self::$serviceId) {
                return;
            }

            $secured = $_REQUEST['s'];
            $unsecured = openssl_decrypt($secured, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);
            $data = json_decode($unsecured, true);


            SecureCookie::setSecureCookie(self::$serviceId, self::getCookieName(), $data['uid'], self::$privateKey, 0, '', '', false, null);

            header('Location: ' . self::getCurrentUrlWithoutArgs());
        }
    }

    
    /**
     * Récupère les données d'authentification à partir du serveur ASPIC
     * @return boolean  Succès ou echec.
     */
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
                self::$extraArguments = $decryptedResults['extraArguments'];

                self::$serverDataGetted = true;

                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    
    /**
     * Retourne le nom du cookie local
     * @return string
     */
    private static function getCookieName() {
        if (self::$cookieName) {
            return self::$cookieName;
        }

        self::$cookieName = md5(self::$serviceId);
        return self::$cookieName;
    }

    
    /**
     * Génère l'url de demande d'authentification à Aspic
     * @param array $extraArguments Données contextuelles liées à la connexion qui seront transmises à Aspic. (Si activé sur le serveur)
     * @return string
     */
    private static function getLoginServerUrl($extraArguments = null) {
        if (self::$serverLoginUrl) {
            return self::$serverLoginUrl;
        }

        $url = self::getBaseServerUrl();

        $secureString = self::$serviceId . '|' . self::getCurrentUrl() . '|' . md5($_SERVER['HTTP_USER_AGENT']);
        $secured = openssl_encrypt($secureString, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);

        $url .= '?sid=' . self::$serviceId . '&s=' . urlencode($secured);

        if ($extraArguments) {
            $extraString = json_encode($extraArguments);
            $extraSecured = openssl_encrypt($extraString, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);
            $extraSecuredOut = openssl_decrypt($extraSecured, self::$encryptMethod, self::$privateKey, false, self::$initializationVector);

            $url .= '&e=' . urlencode($extraSecured);
        }

        self::$serverLoginUrl = $url;

        return $url;
    }

    
    /**
     * Retourne l'url de base du serveur ASPIC
     * @return string
     */
    private static function getBaseServerUrl() {
        $url = 'http';
        if (self::$ssl) {
            $url .= 's';
        }
        $url .= '://' . self::$host;

        return $url;
    }

    
    /**
     * Retourne l'Url courante
     * @return string
     */
    private static function getCurrentUrl() {

        $pageURL = 'http';
        if (isset($_SERVER['https']) && $_SERVER["HTTPS"] == "on") {
            $pageURL .= "s";
        }
        $pageURL .= "://";
        $pageURL .= $_SERVER["SERVER_NAME"] . $_SERVER["REQUEST_URI"];

        return $pageURL;
    }

    
    /**
     * Retourne l'Url courante sans les arguments GET inutiles
     * @return string
     */
    private static function getCurrentUrlWithoutArgs() {

        $currentArgs = $_GET;
        $currentUrl = self::getCurrentUrl();

        $currentUrlSeg = explode('?', $currentUrl);
        $currentUrl = $currentUrlSeg[0];

        $first = true;
        foreach ($currentArgs as $k => $v) {
            if ($k != 's' && $k != 'sid' && !in_array($k, self::$ignoredGetArgs, true)) {
                if ($first) {
                    $currentUrl .= '?' . $k . '=' . $v;
                    $first = false;
                } else {
                    $currentUrl .= '&' . $k . '=' . $v;
                }
            }
        }

        return $currentUrl;
    }

}
