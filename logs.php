<?php


/**
 * Classe de gestion des logs
 * @author Loïc Gerard <lgerard@diatem.net>
 */
class Logs{

    /**
     * Logs initialisés
     * @var boolean
     */
    private static $initialized;

    /**
     * Chemin du fichier d'enregistrement des logs
     * @var string
     */
    private static $log_file;

    /**
     * Pointeur du fichier
     * @var mixed
     */
    private static $fp;

    /**
     * Initialisation des logs
     * @return [type] [description]
     */
    private static function init(){
        if(self::$initialized){
            return;
        }

        self::$log_file = MODULE_ROOT.'/'.ASPIC_LOGS_FILE;
        self::$initialized = true;
    }


    /**
     * Enregistre un log
     * @param  string $message   Texte à enregistrer
     */
    public static function log($message){
        self::init();
        if(!ASPIC_LOGS_ENABLED){
            return;
        }
        self::write($message);
    }


    /**
     * Ecrit dans le fichier
     * @param  string $message Message à enregistrer
     */
    private static function write($message){
        if (!is_resource(self::$fp)) {
            self::open();
        }

        $time = @date('[d/M/Y:H:i:s]');

        // write current time, script name and message to the log file
        fwrite(self::$fp, "$time - $message" . PHP_EOL);

        if(ASPIC_LOGS_INOUTPUT){
            echo $message.'<br>';
        }
    }


    /**
     * Ouvre le fichier en écriture
     */
    private static function open(){
        self::$fp = fopen(self::$log_file, 'a') or exit("Can't open $lfile!");
    }


    /**
     * Ferme le fichier
     */
    private static function close() {
        fclose(self::$fp);
    }
}
