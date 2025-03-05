# PHPGruenbeck

PHPGruenbeck ist eine PHP-Bibliothek für den Zugriff auf die Gruenbeck Cloud API. Sie ermöglicht die Abfrage von Gerätedaten, Parametern und Messwerten von Gruenbeck Wasserenthärtungsanlagen über die myGruenbeck-Cloud.

## Version
1.3

## Funktionen

- **Authentifizierung**: Vollständige Implementierung des OAuth2-Flows mit PKCE
- **Geräteauswahl**: Automatische Erkennung und Filterung von Softliq-Geräten
- **Datenabfrage**: Abrufen von Geräteinformationen, Parametern, Wasser- und Salzverbrauch
- **Parameter-Aktualisierung**: Ändern von Geräteparametern
- **Polling**: Regelmäßige Abfrage von Gerätedaten
- **Token-Management**: Automatische Aktualisierung und Speicherung von Tokens

## Anforderungen

- PHP 7.2 oder höher
- PHP cURL-Erweiterung
- PHP JSON-Erweiterung

## Installation

1. Laden Sie die Datei `PHPGruenbeck.php` herunter
2. Fügen Sie die Datei in Ihr Projekt ein
3. Importieren Sie die Klasse mit `require_once 'PHPGruenbeck.php';`

## Verwendung

### Grundlegende Verwendung

```php
<?php
require_once 'PHPGruenbeck.php';

// Erstellen einer neuen Instanz
$gruenbeck = new PHPGruenbeck('mein_benutzername', 'mein_passwort');

// Anmelden und Gerät auswählen
if ($gruenbeck->login() && $gruenbeck->getMgDevices()) {
    // Daten einmalig abrufen
    $data = $gruenbeck->getData(360, null, true);
    
    // Daten anzeigen
    print_r($data);
}
```

### Kontinuierliches Polling mit Callback

```php
<?php
require_once 'PHPGruenbeck.php';

// Erstellen einer neuen Instanz mit Debug-Modus
$gruenbeck = new PHPGruenbeck('mein_benutzername', 'mein_passwort', true);

// Callback-Funktion zur Verarbeitung der Daten
function processData($data) {
    echo "Neuer Datensatz empfangen am " . date('Y-m-d H:i:s') . "\n";
    
    if (isset($data['device']['serialNumber'])) {
        echo "Gerät: " . $data['device']['serialNumber'] . "\n";
    }
    
    if (isset($data['parameters']['hardness'])) {
        echo "Wasserhärte: " . $data['parameters']['hardness'] . "\n";
    }
    
    // Daten in Datenbank speichern, etc.
}

// Anmelden und Gerät auswählen
if ($gruenbeck->login() && $gruenbeck->getMgDevices()) {
    // Kontinuierliches Polling starten (alle 10 Minuten)
    $gruenbeck->getData(600, 'processData');
}
```

### Token speichern und wiederverwenden

```php
<?php
require_once 'PHPGruenbeck.php';

$gruenbeck = new PHPGruenbeck('mein_benutzername', 'mein_passwort');
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
```

### Parameter aktualisieren

```php
<?php
require_once 'PHPGruenbeck.php';

$gruenbeck = new PHPGruenbeck('mein_benutzername', 'mein_passwort');

if ($gruenbeck->login() && $gruenbeck->getMgDevices()) {
    // Parameter aktualisieren
    $gruenbeck->pushMgParameter(['hardness' => 15]);
    
    // Oder Regeneration starten
    $gruenbeck->pushMgParameter([], 'regenerate');
}
```

### Eigene Log-Handler verwenden

```php
<?php
require_once 'PHPGruenbeck.php';

$gruenbeck = new PHPGruenbeck('mein_benutzername', 'mein_passwort');

// Eigene Log-Handler registrieren
$gruenbeck->setLogCallback('debug', function($message) {
    echo "[DEBUG] " . date('Y-m-d H:i:s') . " - $message\n";
});

$gruenbeck->setLogCallback('error', function($message) {
    echo "[ERROR] " . date('Y-m-d H:i:s') . " - $message\n";
    // In Logdatei schreiben
    file_put_contents('gruenbeck_errors.log', date('Y-m-d H:i:s') . " - $message\n", FILE_APPEND);
});

// Normal verwenden
if ($gruenbeck->login()) {
    // ...
}
```

## API-Referenz

### Konstruktor

```php
__construct($username, $password, $debug = false, $deviceIndex = 0)
```

- `$username`: Der Benutzername für myGruenbeck
- `$password`: Das Passwort für myGruenbeck
- `$debug`: Debug-Modus aktivieren (true/false)
- `$deviceIndex`: Index des zu verwendenden Geräts (wenn mehrere vorhanden)

### Authentifizierung

```php
login()
```
Führt den OAuth2-PKCE-Login durch und erhält Access- und Refresh-Tokens.

```php
alternativeLogin()
```
Alternativer Login-Ansatz, falls der Standard-Login fehlschlägt.

```php
startRefreshToken()
```
Aktualisiert den Access-Token mithilfe des Refresh-Tokens.

```php
saveTokens($filename)
```
Speichert Access- und Refresh-Tokens in einer Datei.

```php
loadTokens($filename)
```
Lädt Tokens aus einer Datei und aktualisiert sie bei Bedarf.

### Gerätemanagement

```php
getMgDevices()
```
Ruft alle verfügbaren Geräte ab und wählt das zu verwendende Gerät aus.

### Datenabfrage

```php
parseMgInfos($endpoint = '')
```
Ruft Daten vom angegebenen Endpunkt ab (z.B. 'parameters', 'measurements/water').

```php
getData($interval = 360, $callback = null, $once = false)
```
Führt eine regelmäßige Abfrage der Gerätedaten durch.

### Parameter-Aktualisierung

```php
pushMgParameter($data, $action = null)
```
Sendet Parameter-Aktualisierungen an das Gerät.

### Hilfsfunktionen

```php
setDebug($debug)
```
Aktiviert oder deaktiviert den Debug-Modus.

```php
setLogCallback($level, $callback)
```
Setzt Callback-Funktionen für verschiedene Log-Level.

```php
getAccessToken()
```
Gibt den aktuellen Access-Token zurück.

```php
getRefreshToken()
```
Gibt den aktuellen Refresh-Token zurück.

```php
getMgDeviceId()
```
Gibt die ID des ausgewählten Geräts zurück.

```php
getDescription($key)
```
Gibt die Beschreibung für einen Parameter zurück.

## Unterstützte Endpunkte

- `''` (leer): Basis-Geräteinformationen
- `'parameters'`: Geräteparameter und Einstellungen
- `'measurements/water'`: Wasserverbrauchsdaten
- `'measurements/salt'`: Salzverbrauchsdaten

## Fehlerbehandlung

Die Klasse enthält umfassende Fehlerbehandlung und Logging-Funktionen. Standardmäßig werden Fehler mit `error_log()` protokolliert. Sie können eigene Log-Handler registrieren, um Fehler zu verarbeiten und zu protokollieren.

## Hinweise

- Das minimale Polling-Intervall beträgt 360 Sekunden (6 Minuten), um API-Limits und Blockierungen zu vermeiden.
- Tokens werden alle 50 Minuten automatisch aktualisiert, um kontinuierlichen Zugriff zu gewährleisten.
- Die Klasse unterstützt nur Softliq-Geräte (wird automatisch gefiltert).

## Lizenz

MIT
