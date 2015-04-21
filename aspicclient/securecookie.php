<?php

use jin\lang\ListTools;

/**
 * Classe de gestion de cookies sécurisés
 */
class SecureCookie {

    /**
     * Méthode de hashage
     * @var string
     */
    private static $hashMethod = 'md5';

    /**
     * Méthode d'encodage
     * @var string
     */
    private static $encodeMethod = 'aes128';

    /**
     * Vecteur d'initialisation utilisé pour l'encodage
     * @var string
     */
    private static $initializationVector = '1234567812345678';

    /**
     * modifie la méthode de hashage
     * @param string $method    Méthode de hashage
     */
    public static function setHashMethod($method) {
        self::$hashMethod = $method;
    }

    /**
     * Modifie la méthode d'encodage
     * @param string $method    Méthode d'encodage.
     */
    public static function setEncodeMethod($method) {
        self::$encodeMethod = $method;
    }

    /**
     * Modifie le vecteur d'initialisation utilisé pour l'encodage
     * @param string $vector    Nouveau vecteur
     */
    public static function setInitializationVector($vector) {
        self::$initializationVector = $vector;
    }

    /**
     * Supprime le cookie
     * @param string $cookiename    Nom du cookie
     */
    public static function delete($cookiename) {
        setcookie($cookiename, '', time() - 3600);
    }

    /**
     * Retourne TRUE si le cookie existe.
     * @param string $cookiename    Nom du cookie
     * @return boolean
     */
    public static function cookieExists($cookiename) {
        return (isset($_SESSION[$cookiename]));
    }

    /**
     * Ecrit un nouveau cookie sécurisé.
     * @param string $serviceId     Service ID Aspic
     * @param string $cookiename    Nom du cookie
     * @param string $value         Valeur à stocker
     * @param string $privateKey    Clé privée
     */
    public static function setSecureCookie($serviceId, $cookiename, $value, $privateKey) {
        $json = json_encode($value);
        $securedValue = openssl_encrypt($json, self::$encodeMethod, $privateKey, false, self::$initializationVector);

        $controlString = $serviceId . '|' . $securedValue . '|' . md5($_SERVER['HTTP_USER_AGENT']);
        $controlString = hash(self::$hashMethod, $controlString);

        self::setUnsecureCookie($cookiename, $securedValue . '|' . $controlString);
    }

    /**
     * Ecrit un cookie non sécurisé (standard)
     * @param string $name cookie name
     * @param string $cookiename    Nom du cookie
     * @param string $value         Valeur à stocker
     */
    public static function setUnsecureCookie($cookiename, $value) {
        $_SESSION[$cookiename] = $value;
    }

    /**
     * Retourne la valeur d'un cookie sécurisé. FALSE si une erreur survient
     * @param string $cookiename    Nom du cookie
     * @param string $serviceId     Service ID
     * @param string $privateKey    Clé privée
     * @param string $md5UserAgent  UserAgent hashé (MD5)
     * @return boolean|string
     */
    public static function getSecureCookie($cookiename, $serviceId, $privateKey, $md5UserAgent = null) {
        if (!isset($_SESSION[$cookiename])) {
            return false;
        }

        $cookieValue = $_SESSION[$cookiename];
        $encoded = self::ListGetAt($cookieValue, 0, '|');
        $control = self::ListGetAt($cookieValue, 1, '|');

        if (!$md5UserAgent) {
            $md5UserAgent = md5($_SERVER['HTTP_USER_AGENT']);
        }

        $controlString = hash(self::$hashMethod, $serviceId . '|' . $encoded . '|' . $md5UserAgent);
        if ($controlString != $control) {
            return false;
        }

        $decrypted = openssl_decrypt($encoded, self::$encodeMethod, $privateKey, false, self::$initializationVector);
        return json_decode($decrypted);
    }

    /**
     * Récupère un élément d'une liste
     * @param string $list  Liste
     * @param tint $index   Index souhaité
     * @param string $delimiter Séparateur
     * @return type
     */
    private static function ListGetAt($list, $index, $delimiter = ',') {
        $arr = self::toArray($list, $delimiter);
        return $arr[$index];
    }

    /**
     * Convertit une liste en tableau
     * @param string $list  Liste source
     * @param string $delimiter	Séparateur
     * @return string
     */
    private static function toArray($list, $delimiter = ',') {
        if ($list == '') {
            return array();
        } else {
            return self::explode($list, $delimiter);
        }
    }

    /** Coupe la chaîne en un tableau
     *
     *  @param  string  $chaine                 Chaîne de caractères
     *  @param  string  $delimiter              [optionel] Caractère ou chaîne utilisée pour découper le tableau. (Si la chaîne est vide ou non fournie la chaîne sera découpée pour chaque caractère)
     *  @return array                       Tableau de chaînes de caractères
     */
    private static function explode($chaine, $delimiter = '') {
        if ($delimiter == '') {
            return str_split($chaine);
        } else {
            return explode($delimiter, $chaine);
        }
    }

}
