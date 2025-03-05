<?php
require_once 'PHPGruenbeck.class.php';

$gruenbeck = new PHPGruenbeck('myuser@email.mail', 'MyPassword');
$tokenFile = 'gruenbeck_tokens.json';

// Versuche zuerst, Token aus Datei zu laden
if (file_exists($tokenFile) && $gruenbeck->loadTokens($tokenFile)) {
    echo "Token aus Datei geladen\n";
} else {
    // Andernfalls neu anmelden
    if ($gruenbeck->login()) {
        echo "Neu angemeldet\n";
        // Token für spätere Verwendung speichern
        $gruenbeck->saveTokens($tokenFile);
    } else {
        die("Anmeldung fehlgeschlagen\n");
    }
}

// Gerät auswählen und Daten abrufen
if ($gruenbeck->getMgDevices()) {
    $data = $gruenbeck->getData(360, null, true);
    print_r($data);
} else {
    echo "Fehler beim Abrufen der Geräte\n";
}
