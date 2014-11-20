<?php

//Permet de désactiver le module temporairement en cas de configuration erronnée.
define('ASPIC_ENABLED', true);
//Trace des logs des action. (à des fins de debug uniquement)
define('ASPIC_LOGS_ENABLED', false);
//Fichier de logs
define('ASPIC_LOGS_FILE', 'logs.txt');
//(Uniquement si ASPIC_LOGS_ENABLED=true) permet de sortir également les logs dans le rendu HTML. (à des fins de debug uniquement)
define('ASPIC_LOGS_INOUTPUT', false);