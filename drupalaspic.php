<?php

include 'aspicclient/aspicclient.php';
include 'logs.php';


class DrupalAspic {

    const LOGIN = 1;
    const LOGOUT = 2;
    const CHECK = 3;

    private static $savedAction = 3;

    public static function init() {
        //Initialisation Aspic
        AspicClient::init(variable_get('drupal_aspic_host'), variable_get('drupal_aspic_serviceid'), variable_get('drupal_aspic_privatekey'), variable_get('drupal_aspic_ssl'));

        global $user;

        //Test if action Logout et authentifié : logout de Drupal
        if (isset($_SERVER['REDIRECT_URL']) && $_SERVER['REDIRECT_URL'] == '/user/logout' && self::isAuthentified()) {
            self::logoutFromDrupal();
        }


        //Test #1 - authentifié Aspic ?
        if (self::isAuthentified()) {
            Logs::log('-----------------------------');
            Logs::log('#1 : authentifié sur Aspic : YES');

            //Test #2 - authentifié Drupal ?
            if ($user->uid) {
                //Authentifié Drupal : Y
                Logs::log('#2 : authentifié sur Drupal : YES');
                
                //Comparaison userId Drupal et userId Aspic
                //test #5
                if ($user->name == AspicClient::getUserId()) {
                    //OK
                    Logs::log('#5 : userID Drupal et userId Aspic communs : YES');
                } else {
                    //Not OK. Deconnexion from Drupal
                    Logs::log('#5 : userID Drupal et userId Aspic communs : NO');
                    Logs::log('ACTION : LOG OUT FROM DRUPAL');
                    self::logoutFromDrupal();
                }
            } else {
                //Autehtifié Drupal : N
                Logs::log('#2 : authentifié sur Drupal : NO');

                //Charge l'utilisateur Drupal
                $drupalUser = user_load_by_name(AspicClient::getUserId());

                //Test #3 - test si le compte Drupal avec ce nom existe
                if ($drupalUser) {
                    //Compte Drupal existe
                    Logs::log('#3 : compte Drupal local existe : YES');
                    
                    //Test si les roles sont justes
                    //On récupère les roles Aspic de l'utilisateur
                    $aspicGroups = AspicClient::getUserGroups();

                    //Stockera les roles à effecter à l'utilisateur
                    $roles = array();

                    //Variable stockant le résultat de la compoaraison des groupes
                    $check = true;

                    if (count($aspicGroups) == 1 && !$aspicGroups[0]) {
                        //Cas particulier. Si pas de groupe retourné par Aspic, groupe le plus bas par défaut.
                        $roles[] = 'authenticated user';

                        if (count($drupalUser->roles) == 1 && $drupalUser->roles[0] == 'authenticated user') {
                            //L'utilisateur Drupal a bien un seul rôle, du niveau le plus bas
                        } else {
                            //L'utilisateur Drupal courant a davantage de rôles
                            $check = false;
                        }
                    } else {
                        //On récupère les rôles Drupal
                        $drupalRoles = user_roles();


                        //Structure permettant de stocker le résultat des checks, uniquement avec des groupes reconnus par Drupal
                        $checkgroups = array();
                        foreach ($aspicGroups as $g) {
                            if($g){
                                foreach($drupalRoles as $dk => $dv){
                                    if($dv == $g){
                                        $checkgroups[$g] = false;
                                    }
                                }
                            }
                        }

                        $testDrupalRoles = $drupalUser->roles;
                        foreach ($testDrupalRoles as $key => $value) {
                            if($value == 'authenticated user'){
                                unset($testDrupalRoles[$key]);
                            }
                        }

                        //Si l'utilisateur Drupal et l'utilisateur Aspic n'ont pas le même nombre de rôles
                        if (count($checkgroups) != count($testDrupalRoles)) {
                            $check = false;
                        }

                        //On compare les rôles de l'utilisateur Drupal et de l'utilisateur Aspic
                        foreach ($drupalUser->roles as $r) {
                            if (isset($checkgroups[$r])) {
                                $checkgroups[$r] = true;
                            }
                        }

                        //Si un ou plus des groupes ne correspond pas
                        foreach ($checkgroups as $g) {
                            if ($g === false) {
                                $check = false;
                            }
                        }

                        //On met à jour la styructure stockant les rôles à attribuer à l'utilisateur Drupal
                        foreach ($checkgroups as $k => $v) {
                            $roles[] = $k;
                        }

                    }

                    //Test #4 - roles Drupal = rôles aspic
                    if ($check) {
                        //Role checking : Y
                        Logs::log('#4 : rôles compte Drupal cohérents avec rôles compte Aspic : YES');
                        Logs::log('ACTION : CONNEXION SUR DRUPAL');
                        //CONNEXION OK
                        
                        //COnnexion
                        self::logInDrupal($drupalUser->uid);
                    } else {
                        //Role checking : N
                        Logs::log('#4 : rôles compte Drupal cohérents avec rôles compte Aspic : NO');
                        Logs::log('ACTION : MISE A JOUR DES DROITS DRUPAL');
                        
                        //On met à jour les droits
                        self::updateUserRoles($drupalUser->uid, $roles);
                        
                        //COnnexion
                        Logs::log('ACTION : CONNEXION SUR DRUPAL');
                        self::logInDrupal($drupalUser->uid);
                    }
                } else {
                    Logs::log('#3 : compte local Drupal existe : N');
                    Logs::log('ACTION : CREATION COMPTE DRUPAL');
                    $roles = self::getUserRoles();
                    $new_user = array(
                        'name' => AspicClient::getUserId(),
                        'pass' => self::randomPassword(),
                        'mail' => AspicClient::getUserId(),
                        'status' => 1
                    );
                    
                    //Enregistrement
                    $account = user_save(null, $new_user);
                    self::updateUserRoles($account->uid, $roles);

                    //connexion
                    Logs::log('ACTION : CONNEXION');
                    self::logInDrupal($account->uid);
                }
            }
        } else {
            //AUTH ASPIC : N
        }
    }

    public static function login() {
        AspicClient::login();
    }

    public static function isAuthentified() {
        return AspicClient::isAuthentified();
    }

    public static function logout() {
        AspicClient::logout();
    }

    private static function logoutFromDrupal(){
        session_destroy();
        self::logout();
        exit;
    }

    private static function logInDrupal($drupalUId){
        global $user;
        $user = user_load($drupalUId);

        $login_array = array('name' => $user->name);
        user_login_finalize($login_array);
    }

    private static function randomPassword(){
        $pass = '';
        for($i = 0; $i<32; $i++){
            $pass .= rand(0,9);
        }
        return $pass;
    }

    private static function getUserRoles(){
        $roles = array();
        $aspicGroups = AspicClient::getUserGroups();
        $drupalRoles = user_roles();

        foreach($aspicGroups as $g){
            foreach($drupalRoles as $dk => $dv){
                if($dv == $g){
                    $roles[] = $g;
                }
            }
        }

        return $roles;
    }

    private static function updateUserRoles($drupalUserId, $roles){
        $myuser = user_load($drupalUserId);
        //On récupère les droits courants
        $myuserroles = $myuser->roles;
        //On modifie les droits
        foreach ($myuserroles as $k => $ur) {
            unset($myuserroles[$k]);
        }
        foreach ($roles as $r) {
            if($r != 'authenticated user'){
                $myuserroles[] = $r;
            }
            
        }

        //On met à jour l'utilisateur
        user_save($myuser, array('roles' => $myuserroles));

        $myuser = user_load($drupalUserId);
    }

}
