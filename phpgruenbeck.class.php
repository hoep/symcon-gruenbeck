<?php
/**
 * PHPGruenbeck Klasse
 * 
 * Eine PHP-Implementierung für den Zugriff auf die Gruenbeck Cloud API mit 
 * Authentifizierung und Code Challenge. Sie bietet Funktionen zum Abrufen 
 * von Gerätedaten und zum regelmäßigen Pollen der API.
 * 
 * 
 * @version 1.4
 * @license MIT
 */
class PHPGruenbeck {
    /**
     * Die API-Version für SD
     * @var string
     */
    private $sdVersion = '2024-05-02';
    
    /**
     * Die API-Version für SE
     * @var string
     */
    private $seVersion = '2024-05-02';
    
    /**
     * Der User-Agent für API-Anfragen
     * @var string
     */
    private $userAgent = 'ioBroker 41';
    
    /**
     * Der Benutzername für myGruenbeck
     * @var string
     */
    private $username;
    
    /**
     * Das Passwort für myGruenbeck
     * @var string
     */
    private $password;
    
    /**
     * Der Access-Token für API-Anfragen
     * @var string
     */
    private $accessToken = '';
    
    /**
     * Der Refresh-Token für die Token-Aktualisierung
     * @var string
     */
    private $refreshToken = '';
    
    /**
     * Die Tenant-ID aus der Auth-Anfrage
     * @var string
     */
    private $tenant = '';
    
    /**
     * Die Geräte-ID des ausgewählten Geräts
     * @var string
     */
    private $mgDeviceId = '';
    
    /**
     * Die Geräte-ID mit entfernten Sonderzeichen
     * @var string
     */
    private $mgDeviceIdEscaped = '';
    
    /**
     * Index des zu verwendenden Geräts
     * @var int
     */
    private $deviceIndex = 0;
    
    /**
     * Debug-Modus aktivieren/deaktivieren
     * @var bool
     */
    private $debug = false;
    
    /**
     * Beschreibungen für Parameter (aus descriptions.js)
     * @var array
     */
    private $descriptions = [];
    
    /**
     * Log-Callbacks für verschiedene Log-Level
     * @var array
     */
    private $logCallbacks = [
        'debug' => null,
        'info' => null,
        'error' => null
    ];

    /**
     * Konstruktor
     * 
     * @param string $username Der myGruenbeck Benutzername
     * @param string $password Das myGruenbeck Passwort
     * @param bool $debug Debug-Modus aktivieren
     * @param int $deviceIndex Index des zu verwendenden Geräts (falls mehrere vorhanden)
     */
    public function __construct($username, $password, $debug = false, $deviceIndex = 0) {
        $this->username = $username;
        $this->password = $password;
        $this->debug = $debug;
        $this->deviceIndex = $deviceIndex;
        $this->loadDescriptions();
    }
    
    /**
     * Setzt Callback-Funktionen für Logs
     * 
     * @param string $level Log-Level ('debug', 'info', 'error')
     * @param callable $callback Callback-Funktion, die den Log-String erhält
     * @return bool Erfolg
     */
    public function setLogCallback($level, $callback) {
        if (!isset($this->logCallbacks[$level])) {
            return false;
        }
        
        if (!is_callable($callback) && $callback !== null) {
            return false;
        }
        
        $this->logCallbacks[$level] = $callback;
        return true;
    }
    
    /**
     * Lädt die Beschreibungen für Parameter
     * Die vollständige Liste aus der descriptions.js-Datei
     */
    private function loadDescriptions() {
        $this->descriptions = [
            'icalcreg1' => '[hh:mm] Time of regeneration 1',
            'icalcreg2' => '[hh:mm] Time of regeneration 2',
            'icalcreg3' => '[hh:mm] Time of regeneration 3',
            'icalcregd' => '[yyyy.mm.dd] Date',
            'idos' => 'Status Dosiergerät',
            'ierrmemclear' => '[yyyy.mm.dd hh:mm] Error memory last deleted',
            'ihwversioncl' => 'Hardware version',
            'iiqcomfort' => 'An IQ-Comfort angeschlossene Geräte',
            'ilastservice' => '[yyyy.mm.dd] Last maintenance',
            'isncu' => 'Controller serial number',
            'istartup' => '[yyyy.mm.dd] Date of Start-up',
            'iswupdate' => 'Software update',
            'iswversion' => 'Software version',
            'itimezone' => '[h] Current time zone',
            'itype' => 'System type',
            'iurlcloud1' => 'URL Cloud',
            'mcapacity' => '[m³x°dH] Capacity figure',
            'mcountreg' => 'regeneration counter',
            'mcountwater1' => '[l] Soft water exchanger 1',
            'mcountwater2' => '[l] Soft water exchanger 2',
            'mcountwatertank' => '[l] Make-up water volume',
            'mcurrent' => '[mA] Chlorine current',
            'mendreg1' => '[hh:mm] Last regeneration Exchanger 1',
            'mendreg2' => '[hh:mm] Last regeneration Exchanger 2',
            'mflow1' => '[m³/h] Flow rate exch. 1',
            'mflow2' => '[m³/h] Flow rate exch. 2',
            'mflowblend' => '[m³/h] Blending flow rate',
            'mflowexc' => '[Min] during',
            'mflowexc1reg2' => '[Min]',
            'mflowexc2reg1' => '[Min]',
            'mflowmax' => '[m³/h] Flow rate peak value',
            'mflowmax1reg2' => '[m³/h] Exchanger 1 peak value',
            'mflowmax2reg1' => '[m³/h] Exchanger 2 peak value',
            'mflowreg1' => '[l/h] Regeneration flow rate Exchanger 1',
            'mflowreg2' => '[l/h] Regeneration flow rate Exchanger 2',
            'mhardsoftw' => '[°dh] Actual value soft water hardness',
            'mlifeadsorb' => '[%] Adsorber exhausted by',
            'mmaint' => '[d] Perform maintenance in',
            'mregpercent1' => '[%]',
            'mregpercent2' => '[%]',
            'mregstatus' => 'Regeneration step',
            'mremregstep' => 'Remaining amount / time of current regeneration step',
            'mrescapa1' => '[m³] Soft water Exchanger 1',
            'mrescapa2' => '[m³] Soft water Exchanger 2',
            'mresidcap1' => '[%] Residual capacity 1',
            'mresidcap2' => '[%] Residual capacity 2',
            'mreswatadmod' => '[m³] Adsorber remaining amount of water',
            'msaltrange' => '[d] Salt-reach',
            'msaltusage' => '[kg] salt consumption',
            'mstep1' => 'Step indication regeneration valve 1',
            'mstep2' => 'Step indication regeneration valve 2',
            'pbackwash' => '[l] Backwash',
            'pbuzzer' => 'Audio signal',
            'pbuzzfrom' => '[hh:mm] Audio signal release from',
            'pbuzzto' => '[hh:mm] Audio signal release until',
            'pcfcontact' => 'Function fault signal contact',
            'pclearcntreg' => 'Reset regeneration counter',
            'pclearcntwater' => 'Reset water meter',
            'pclearerrmem' => 'Delete error memory',
            'pcurrent' => '[mA] Setpoint current',
            'pdate' => '[yyyy.mm.dd] Current date',
            'pdlstauto' => 'Switch-over DST to ST',
            'pforcedregdist' => '[d] Interval of forced regeneration',
            'pfreqblendvalve' => '[Hz] End frequency blending valve',
            'pfreqregvalve' => '[Hz] End frequency regeneration valve',
            'phunit' => 'Hardness unit',
            'pknx' => 'KNX connection',
            'planguage' => 'Current language',
            'pled' => 'Illuminated LED ring',
            'pledatsaltpre' => 'Illuminated LED ring flashes on signal',
            'pledbright' => '[%] Brightness',
            'pload' => '[mAMin] Charge',
            'pmailadress' => '',
            'pmaintint' => '[d] Maintenance interval',
            'pmaxdurdisinfect' => '[Min] Longest switch-on time Cl cell',
            'pmaxresdurreg' => '[Min] Max Remaining time regeneration',
            'pmaxvolmaxcap' => '[l] Max. filling volume largest cap',
            'pmaxvolmincap' => '[l] Max. filling volume smallest cap',
            'pminvolmaxcap' => '[l] Min. filling volume largest cap',
            'pminvolmincap' => '[l] Min. filling volume smallest cap',
            'pmode' => '',
            'pmodedesinf' => 'Activate/deactivate chlorine cell',
            'pmodefr' => 'Indiv. Operating mode Friday',
            'pmodemo' => 'Indiv. Operating mode Monday',
            'pmodesa' => 'Indiv. Operating mode Saturday',
            'pmodesu' => 'Indiv. Operating mode Sunday',
            'pmodeth' => 'Indiv. Operating mode Thursday',
            'pmodetu' => 'Indiv. Operating mode Tuesday',
            'pmodewe' => 'Indiv. Operating mode Wednesday',
            'pmonblend' => 'Blending monitoring',
            'pmondisinf' => 'Disinfection monitoring',
            'pmonflow' => 'Monitoring of nominal flow',
            'pmonregmeter' => '[Min] Regeneration monitoring time',
            'pmonsalting' => '[Min] Salting monitoring time',
            'pname' => 'Name',
            'pnomflow' => '[m³/h] Nominal flow rate',
            'pntpsync' => 'Get date/time automatically (NTP)',
            'poverload' => 'System overloaded',
            'ppowerfail' => 'Reaction to power failure > 5 min',
            'pprateblending' => '[l/Imp] Blending water meter pulse rate',
            'pprateregwater' => '[l/Imp] Regeneration water meter pulse rate',
            'ppratesoftwater' => '[l/Imp] Soft water meter pulse rate',
            'pprogin' => 'Programmable input function',
            'pprogout' => 'Programmable output function',
            'prawhard' => '[°dH] Raw water hardness',
            'pregmo1' => '[hh:mm] Define time of regeneration 1',
            'pregmo2' => '[hh:mm] Define time of regeneration 2',
            'pregmo3' => '[hh:mm] Define time of regeneration 3',
            'pregmode' => 'Time of regeneration',
            'prescaplimit' => '[%] Residual capacity limit value',
            'prinsing' => '[Min] Slow rinse',
            'psetcapfr' => '[m³x°dH] Capacity figure Friday',
            'psetcapmo' => '[m³x°dH] Capacity figure Monday',
            'psetcapsa' => '[m³x°dH] Capacity figure Saturday',
            'psetcapsu' => '[m³x°dH] Capacity figure Sunday',
            'psetcapth' => '[m³x°dH] Capacity figure Thursday',
            'psetcaptu' => '[m³x°dH] Capacity figure Tuesday',
            'psetcapwe' => '[m³x°dH] Capacity figure Wednesday',
            'psetsoft' => '[°dH] Setpoint of soft water hardness',
            'ptelnr' => 'Tel. no.',
            'ptime' => '[hh:mm] Current time',
            'pvolume' => '[m³] Adsorber treatment volume',
            'pwashingout' => '[l] Washing out',
        ];
    }
    
    /**
     * Debug-Modus aktivieren oder deaktivieren
     * 
     * @param bool $debug
     */
    public function setDebug($debug) {
        $this->debug = $debug;
    }
    
    /**
     * Debugnachricht protokollieren
     * 
     * @param string $message Die zu protokollierende Nachricht
     */
    private function logDebug($message) {
        if ($this->logCallbacks['debug']) {
            call_user_func($this->logCallbacks['debug'], $message);
            return;
        }
        
        if ($this->debug) {
            error_log("[DEBUG] " . $message);
        }
    }
    
    /**
     * Fehlernachricht protokollieren
     * 
     * @param string $message Die zu protokollierende Fehlermeldung
     */
    private function logError($message) {
        if ($this->logCallbacks['error']) {
            call_user_func($this->logCallbacks['error'], $message);
            return;
        }
        
        error_log("[ERROR] " . $message);
    }
    
    /**
     * Infonachricht protokollieren
     * 
     * @param string $message Die zu protokollierende Info
     */
    private function logInfo($message) {
        if ($this->logCallbacks['info']) {
            call_user_func($this->logCallbacks['info'], $message);
            return;
        }
        
        if ($this->debug) {
            error_log("[INFO] " . $message);
        }
    }
    
    /**
     * Erzeugt einen Code Verifier und Code Challenge für PKCE
     * 
     * Diese Funktion generiert ein zufälliges Token (Code Verifier) und
     * den entsprechenden Code Challenge durch SHA-256 Hashing, der für die
     * OAuth2-Authentifizierung mit PKCE benötigt wird.
     * 
     * @return array [code_verifier, code_challenge]
     */
    private function getCodeChallenge() {
        $hash = '';
        $result = '';
        
        // Generieren eines gültigen Code Verifier und Challenge ohne +, / oder = Zeichen
        while (
            $hash === '' || 
            strpos($hash, '+') !== false || 
            strpos($hash, '/') !== false || 
            strpos($hash, '=') !== false ||
            strpos($result, '+') !== false || 
            strpos($result, '/') !== false
        ) {
            $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $result = '';
            
            // 64 zufällige Zeichen generieren
            for ($i = 64; $i > 0; --$i) {
                $result .= $chars[rand(0, strlen($chars) - 1)];
            }
            
            // Base64-Encoding und Entfernen der Padding-Zeichen
            $result = base64_encode($result);
            $result = rtrim($result, '=');
            
            // SHA-256-Hash erstellen und als Base64 kodieren
            $hash = base64_encode(hash('sha256', $result, true));
            $hash = substr($hash, 0, strlen($hash) - 1);
        }
        
        return [$result, $hash];
    }
    
    /**
     * Führt den Login-Prozess durch, um Access- und Refresh-Tokens zu erhalten
     * 
     * Diese Funktion implementiert den kompletten OAuth2 PKCE Authentifizierungsfluss
     * für die Gruenbeck API. Sie umfasst mehrere Schritte:
     * 1. Generieren des Code Challenge
     * 2. Initiieren des Authentifizierungsflusses
     * 3. Übermitteln der Anmeldedaten
     * 4. Bestätigen der Anmeldung
     * 5. Austausch des Autorisierungscodes gegen Tokens
     * 
     * @return bool Erfolg
     */
    public function login() {
        $this->logInfo('Starte Login-Prozess');
        
        // Code Challenge für PKCE generieren
        list($code_verifier, $codeChallenge) = $this->getCodeChallenge();
        
        // Initialer Request, um CSRF-Token und Session-Cookies zu erhalten
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://gruenbeckb2c.b2clogin.com/a50d35c1-202f-4da7-aa87-76e51a3098c6/b2c_1a_signinup/oauth2/v2.0/authorize?' . 
            'x-client-Ver=0.8.0&state=NjkyQjZBQTgtQkM1My00ODBDLTn3MkYtOTZCQ0QyQkQ2NEE5&client_info=1&response_type=code&code_challenge_method=S256&x-app-name=Gr%C3%BCnbeck&x-client-OS=14.3&x-app-ver=1.2.1&scope=https%3A%2F%2Fgruenbeckb2c.onmicrosoft.com%2Fiot%2Fuser_impersonation%20openid%20profile%20offline_access&x-client-SKU=MSAL.iOS&' . 
            'code_challenge=' . $codeChallenge . '&x-client-CPU=64&client-request-id=F2929DED-2C9D-49F5-A0F4-31215427667C&redirect_uri=msal5a83cc16-ffb1-42e9-9859-9fbf07f36df8%3A%2F%2Fauth&client_id=5a83cc16-ffb1-42e9-9859-9fbf07f36df8&haschrome=1&return-client-request-id=true&x-client-DM=iPhone');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding: gzip, deflate', // "br" entfernt, da PHP möglicherweise Brotli nicht unterstützt
            'Connection: keep-alive',
            'Accept-Language: de-de',
            'User-Agent: ' . $this->userAgent
        ]);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true); // Folge Umleitungen automatisch
        curl_setopt($ch, CURLOPT_ENCODING, ""); // Aktiviert automatische Dekomprimierung
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $body = substr($response, $headerSize);
        
        if (curl_errno($ch)) {
            $this->logError("Curl-Fehler: " . curl_error($ch));
            curl_close($ch);
            return false;
        }
        
        curl_close($ch);
        
        if ($httpCode !== 200) {
            $this->logError("Initialer Auth-Request fehlgeschlagen mit Code: $httpCode");
            return false;
        }
        
        // Debug: Ersten Teil der Antwort anzeigen
        $this->logDebug("Antwort (erste 300 Zeichen): " . substr($body, 0, 300));
        
        // Versuche mehrere Muster für die Extraktion
        $csrf = null;
        $transId = null;
        $policy = null;
        
        // Versuch 1: Standard-JSON-Muster
        if (preg_match('/csrf":\s*"([^"]+)"/', $body, $matches)) {
            $csrf = $matches[1];
        } elseif (preg_match('/csrf=([^&"]+)/', $body, $matches)) {
            $csrf = $matches[1];
        } elseif (preg_match('/name="csrf"\s+value="([^"]+)"/', $body, $matches)) {
            $csrf = $matches[1];
        }
        
        if (preg_match('/transId":\s*"([^"]+)"/', $body, $matches)) {
            $transId = $matches[1];
        } elseif (preg_match('/transId=([^&"]+)/', $body, $matches)) {
            $transId = $matches[1];
        } elseif (preg_match('/name="transId"\s+value="([^"]+)"/', $body, $matches)) {
            $transId = $matches[1];
        }
        
        if (preg_match('/policy":\s*"([^"]+)"/', $body, $matches)) {
            $policy = $matches[1];
        } elseif (preg_match('/p=([^&"]+)/', $body, $matches)) {
            $policy = $matches[1];
        } elseif (preg_match('/name="policy"\s+value="([^"]+)"/', $body, $matches)) {
            $policy = $matches[1];
        }
        
        if (preg_match('/tenant":\s*"([^"]+)"/', $body, $matches)) {
            $this->tenant = $matches[1];
        } elseif (preg_match('/tenant=([^&"]+)/', $body, $matches)) {
            $this->tenant = $matches[1];
        } elseif (preg_match('/"tenant":"([^"]+)"/', $body, $matches)) {
            $this->tenant = $matches[1];
        }
        
        // Versuch 2: HTML-Attribute
        if (!$csrf && preg_match('/<input[^>]+name="(?:csrf|x-csrf-token)"[^>]+value="([^"]+)"/', $body, $matches)) {
            $csrf = $matches[1];
        }
        
        // Versuch 3: URLs im Body
        if (!$policy && preg_match('/\/b2c_1a_signinup\/([^\/&"]+)\//', $body, $matches)) {
            $policy = $matches[1];
        }
        
        if (!$this->tenant && preg_match('/\/([^\/]+)\/SelfAsserted/', $body, $matches)) {
            $this->tenant = $matches[1];
        }
        
        // Extrahiere auch den tx-Parameter aus URLs
        if (!$transId && preg_match('/\?tx=([^&"]+)/', $body, $matches)) {
            $transId = $matches[1];
        }
        
        // Debug-Informationen
        $this->logDebug("Extrahierte Werte: CSRF=$csrf, TransID=$transId, Policy=$policy, Tenant={$this->tenant}");
        
        if (!$csrf || !$transId || !$policy || !$this->tenant) {
            $this->logError("Konnte erforderliche Token nicht aus der Antwort extrahieren");
            return false;
        }
        
        $this->logInfo("Login Schritt 1 abgeschlossen");
        $this->logDebug("CSRF: $csrf, TransID: $transId, Policy: $policy, Tenant: {$this->tenant}");
        
        // Cookies extrahieren
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $response, $matches);
        $cookies = [];
        foreach($matches[1] as $item) {
            $cookies[] = $item;
        }
        $cookieString = implode('; ', $cookies);
        
        // Zweiter Request - Anmeldedaten senden
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://gruenbeckb2c.b2clogin.com{$this->tenant}/SelfAsserted?tx=$transId&p=$policy");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'request_type' => 'RESPONSE',
            'signInName' => $this->username,
            'password' => $this->password
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
            "X-CSRF-TOKEN: $csrf",
            'Accept: application/json, text/javascript, */*; q=0.01',
            'X-Requested-With: XMLHttpRequest',
            'Origin: https://gruenbeckb2c.b2clogin.com',
            "Cookie: $cookieString",
            'User-Agent: ' . $this->userAgent
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        
        curl_close($ch);
        
        // Debug-Informationen für den zweiten Schritt
        $this->logDebug("Login Schritt 2 - Status Code: $httpCode");
        $this->logDebug("Login Schritt 2 - Response Body: " . substr($body, 0, 300));
        
        // Überprüfen, ob die Antwort einen Fehler enthält
        $responseData = json_decode($body, true);
        // Status wird als String zurückgegeben, nicht als Integer
        if (isset($responseData['status']) && $responseData['status'] != "200") {
            $this->logError("Login fehlgeschlagen: " . ($responseData['message'] ?? 'Unbekannter Fehler'));
            return false;
        }
        
        if ($httpCode !== 200) {
            $this->logError("Anmeldedaten-Übermittlung fehlgeschlagen mit Code: $httpCode");
            return false;
        }
        
        $this->logInfo("Login Schritt 2 abgeschlossen");
        
        // Neue Cookies extrahieren und mit vorhandenen Cookies kombinieren
        preg_match_all('/^Set-Cookie:\s*([^;]*)/mi', $response, $matches);
        $newCookies = [];
        foreach($matches[1] as $item) {
            $newCookies[] = $item;
        }
        $cookieString = implode('; ', array_merge($cookies, $newCookies));
        $cookieString .= "; x-ms-cpim-csrf=$csrf";
        
        // Kurze Pause zwischen den Anfragen hinzufügen (manchmal nötig für APIs)
        usleep(500000); // 500ms Pause
        
        // Dritter Request - Login bestätigen
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://gruenbeckb2c.b2clogin.com{$this->tenant}/api/CombinedSigninAndSignup/confirmed?csrf_token=$csrf&tx=$transId&p=$policy");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        // Wichtig: Keine automatische Weiterleitung, da wir den Redirect-Header auswerten müssen
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Encoding: gzip, deflate',
            'Connection: keep-alive',
            'Accept-Language: de-de',
            "Cookie: $cookieString",
            'User-Agent: ' . $this->userAgent
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        // Extrahiere alle Header
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $header = substr($response, 0, $headerSize);
        $body = substr($response, $headerSize);
        
        $this->logDebug("Response-Header: " . substr($header, 0, 500) . "...");
        $this->logDebug("Response-Body: " . substr($body, 0, 300) . "...");
        
        // Hole die Location-Header (bei 302 Redirect)
        $location = "";
        if (preg_match('/Location: ([^\r\n]+)/i', $header, $matches)) {
            $location = $matches[1];
            $this->logDebug("Location-Header gefunden: $location");
        }
        
        curl_close($ch);
        
        // 302 Redirect mit Code erwartet
        if ($httpCode !== 302) {
            $this->logError("Bestätigungsanfrage fehlgeschlagen, 302 erwartet, aber $httpCode erhalten");
            return false;
        }
        
        // Check for error in the redirect URL
        if ($this->checkForError($location)) {
            $this->logError("Login fehlgeschlagen: Fehler in der Redirect-URL");
            return false;
        }
        
        // Versuchen Sie verschiedene Muster, um den Code zu extrahieren
        $code = null;
        
        // Suche in Location-Header (Priorität)
        if (!empty($location)) {
            // Verschiedene Muster für Code-Extraktion aus der URL
            if (preg_match('/code=([^&]+)/', $location, $matches)) {
                $code = $matches[1];
            } elseif (preg_match('/code%3D([^&]+)/', $location, $matches)) {
                $code = $matches[1];
            } elseif (preg_match('/code%3d([^&]+)/', $location, $matches)) {
                $code = $matches[1];
            }
        }
        
        // Suche im Body als Fallback
        if (!$code) {
            if (preg_match('/code=([^&"]+)/', $body, $matches)) {
                $code = $matches[1];
            } elseif (preg_match('/code%3D([^&"]+)/i', $body, $matches)) {
                $code = $matches[1];
            } elseif (preg_match('/code%3d([^&"]+)/i', $body, $matches)) {
                $code = $matches[1];
            } elseif (preg_match('/\?code=([^&"]+)/', $body, $matches)) {
                $code = $matches[1];
            }
        }
        
        // Suche im gesamten Response als letzter Ausweg
        if (!$code) {
            if (preg_match('/code=([^&"]+)/', $response, $matches)) {
                $code = $matches[1];
            } elseif (preg_match('/code%3D([^&"]+)/i', $response, $matches)) {
                $code = $matches[1];
            } elseif (preg_match('/code%3d([^&"]+)/i', $response, $matches)) {
                $code = $matches[1];
            }
        }
        
        if (!$code) {
            $this->logError("Konnte Autorisierungscode nicht extrahieren");
            return false;
        }
        
        $this->logDebug("Extrahierter Autorisierungscode: $code");
        
        // Letzter Request - Code gegen Tokens tauschen
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://gruenbeckb2c.b2clogin.com{$this->tenant}/oauth2/v2.0/token");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'client_info' => '1',
            'scope' => 'https://gruenbeckb2c.onmicrosoft.com/iot/user_impersonation openid profile offline_access',
            'code' => $code,
            'grant_type' => 'authorization_code',
            'code_verifier' => $code_verifier,
            'redirect_uri' => 'msal5a83cc16-ffb1-42e9-9859-9fbf07f36df8://auth',
            'client_id' => '5a83cc16-ffb1-42e9-9859-9fbf07f36df8'
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: gruenbeckb2c.b2clogin.com',
            'x-client-SKU: MSAL.iOS',
            'Accept: application/json',
            'x-client-OS: 14.3',
            'x-app-name: Grünbeck',
            'x-client-CPU: 64',
            'x-app-ver: 1.2.0',
            'Accept-Language: de-de',
            'client-request-id: F2929DED-2C9D-49F5-A0F4-31215427667C',
            'x-ms-PkeyAuth: 1.0',
            'x-client-Ver: 0.8.0',
            'x-client-DM: iPhone',
            'User-Agent: Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0',
            'return-client-request-id: true'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            $this->logError("Token-Austausch fehlgeschlagen mit Code: $httpCode");
            return false;
        }
        
        $tokenData = json_decode($response, true);
        if (!isset($tokenData['access_token']) || !isset($tokenData['refresh_token'])) {
            $this->logError("Konnte Tokens nicht erhalten");
            return false;
        }
        
        $this->accessToken = $tokenData['access_token'];
        $this->refreshToken = $tokenData['refresh_token'];
        
        $this->logInfo("Login erfolgreich");
        
        return true;
    }

    /**
     * Prüft, ob die Antwort einen Fehler enthält und handhabt ihn entsprechend
     * 
     * @param string $response Die API-Antwort
     * @return bool True wenn ein Fehler gefunden wurde
     */
    private function checkForError($response) {
        if (strpos($response, 'error=') !== false) {
            $this->logDebug("Fehler in der Antwort gefunden");
            
            // Versuche, den Fehlercode und die Beschreibung zu extrahieren
            if (preg_match('/error=([^&]+)/', $response, $errorMatches) && 
                preg_match('/error_description=([^&]+)/', $response, $descMatches)) {
                
                $error = urldecode($errorMatches[1]);
                $description = urldecode($descMatches[1]);
                
                $this->logError("API-Fehler: $error - $description");
                return true;
            }
            
            $this->logError("Unspezifizierter API-Fehler in der Antwort");
            return true;
        }
        
        return false;
    }
    
    /**
     * Ruft die Liste der Geräte ab und wählt das zu verwendende Gerät aus
     * 
     * Diese Funktion ruft alle Geräte des Benutzers ab, filtert nach "soft" Geräten
     * und wählt das entsprechende Gerät basierend auf dem konfigurierten Index aus.
     * 
     * @return bool Erfolg
     */
    public function getMgDevices() {
        if (!$this->accessToken) {
            $this->logError("Nicht authentifiziert. Zuerst login() aufrufen.");
            return false;
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://prod-eu-gruenbeck-api.azurewebsites.net/api/devices?api-version=" . $this->sdVersion);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: prod-eu-gruenbeck-api.azurewebsites.net',
            'Accept: application/json, text/plain, */*',
            'User-Agent: Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0',
            "Authorization: Bearer {$this->accessToken}",
            'Accept-Language: de-de',
            'cache-control: no-cache'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            $this->logError("Fehler beim Abrufen der Geräte mit Code: $httpCode");
            return false;
        }
        
        $devices = json_decode($response, true);
        if (!is_array($devices) || empty($devices)) {
            $this->logError("Keine Geräte gefunden oder ungültige Antwort");
            return false;
        }
        
        $this->logInfo("Gefunden: " . count($devices) . " Geräte");
        
        // Nach softliq Geräten filtern
        $filteredDevices = array_filter($devices, function($device) {
            return stripos($device['id'], 'soft') !== false;
        });
        
        $this->logInfo("Gefiltert auf " . count($filteredDevices) . " Geräte");
        
        if (empty($filteredDevices)) {
            $this->logError("Keine softliq Geräte gefunden");
            return false;
        }
        
        // Konvertieren in indiziertes Array für einfacheren Zugriff
        $filteredDevices = array_values($filteredDevices);
        
        // Ausgewähltes Gerät verwenden
        if (!isset($filteredDevices[$this->deviceIndex])) {
            $this->logError("Geräte-Index {$this->deviceIndex} ist nicht vorhanden, verwende Index 0");
            $this->deviceIndex = 0;
        }
        
        $device = $filteredDevices[$this->deviceIndex];
        $this->mgDeviceId = $device['id'];
        $this->mgDeviceIdEscaped = str_replace('/', '', $this->mgDeviceId);
        
        $this->logInfo("Verwende Gerät: {$this->mgDeviceId} (Name: {$device['name']})");
        
        return true;
    }
    
    /**
     * Ruft Geräteinformationen von einem bestimmten Endpunkt ab
     * 
     * @param string $endpoint Optionaler Endpunkt-Pfad
     * @return array|false Gerätedaten oder false bei Fehler
     */
    public function parseMgInfos($endpoint = '') {
        if (!$this->accessToken || !$this->mgDeviceId) {
            $this->logError("Nicht authentifiziert oder kein Gerät ausgewählt");
            return false;
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://prod-eu-gruenbeck-api.azurewebsites.net/api/devices/{$this->mgDeviceId}/{$endpoint}?api-version=" . $this->sdVersion);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: prod-eu-gruenbeck-api.azurewebsites.net',
            'Accept: application/json, text/plain, */*',
            'User-Agent: ' . $this->userAgent,
            "Authorization: Bearer {$this->accessToken}",
            'Accept-Language: de-de',
            'cache-control: no-cache'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            $this->logError("Fehler beim Abrufen von Infos für Endpunkt '$endpoint' mit Code: $httpCode");
            return false;
        }
        
        $data = json_decode($response, true);
        if ($data === null) {
            $this->logError("Ungültige JSON-Antwort für Endpunkt '$endpoint'");
            return false;
        }
        
        $this->logDebug("Daten für Endpunkt '$endpoint' erfolgreich abgerufen");
        return $data;
    }
    
    /**
     * Aktualisiert die Gerätedaten (Polling)
     * 
     * @return bool Erfolg
     */
    public function refreshSD() {
        if (!$this->accessToken || !$this->mgDeviceId) {
            $this->logError("Nicht authentifiziert oder kein Gerät ausgewählt");
            return false;
        }
        
        $this->logDebug("Aktualisiere SD-Daten");
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://prod-eu-gruenbeck-api.azurewebsites.net/api/devices/{$this->mgDeviceId}/realtime/refresh?api-version=" . $this->sdVersion);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, '{}');
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: prod-eu-gruenbeck-api.azurewebsites.net',
            'Accept: application/json, text/plain, */*',
            'User-Agent: Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0',
            "Authorization: Bearer {$this->accessToken}",
            'Accept-Language: de-de'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 400) {
            $this->logError("Fehler beim Aktualisieren der SD-Daten mit Code: $httpCode");
            return false;
        }
        
        return true;
    }
    
    /**
     * Betritt das SD-Gerät für die Datensammlung
     * 
     * @return bool Erfolg
     */
    public function enterSD() {
        if (!$this->accessToken || !$this->mgDeviceId) {
            $this->logError("Nicht authentifiziert oder kein Gerät ausgewählt");
            return false;
        }
        
        $this->logDebug("Betrete SD");
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://prod-eu-gruenbeck-api.azurewebsites.net/api/devices/{$this->mgDeviceId}/realtime/enter?api-version=" . $this->sdVersion);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, '{}');
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: prod-eu-gruenbeck-api.azurewebsites.net',
            'Accept: application/json, text/plain, */*',
            'User-Agent: Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0',
            "Authorization: Bearer {$this->accessToken}",
            'Accept-Language: de-de'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 400) {
            $this->logError("Fehler beim Betreten des SD mit Code: $httpCode");
            return false;
        }
        
        return true;
    }
    
    /**
     * Verlässt das SD-Gerät
     * 
     * @return bool Erfolg
     */
    public function leaveSD() {
        if (!$this->accessToken || !$this->mgDeviceId) {
            $this->logError("Nicht authentifiziert oder kein Gerät ausgewählt");
            return false;
        }
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://prod-eu-gruenbeck-api.azurewebsites.net/api/devices/{$this->mgDeviceId}/realtime/leave?api-version=" . $this->sdVersion);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, '{}');
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: prod-eu-gruenbeck-api.azurewebsites.net',
            'Accept: application/json, text/plain, */*',
            'User-Agent: Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0',
            "Authorization: Bearer {$this->accessToken}",
            'Accept-Language: de-de'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 400) {
            $this->logError("Fehler beim Verlassen des SD mit Code: $httpCode");
            return false;
        }
        
        return true;
    }
    
    /**
     * Aktualisiert den Access-Token
     * 
     * @return bool Erfolg
     */
    public function startRefreshToken() {
        if (!$this->refreshToken || !$this->tenant) {
            $this->logError("Kein Refresh-Token oder Tenant verfügbar");
            return false;
        }
        
        $this->logDebug("Starte Token-Aktualisierung");
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://gruenbeckb2c.b2clogin.com{$this->tenant}/oauth2/v2.0/token");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
            'client_id' => '5a83cc16-ffb1-42e9-9859-9fbf07f36df8',
            'scope' => 'https://gruenbeckb2c.onmicrosoft.com/iot/user_impersonation openid profile offline_access',
            'refresh_token' => $this->refreshToken,
            'client_info' => '1',
            'grant_type' => 'refresh_token'
        ]));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: gruenbeckb2c.b2clogin.com',
            'x-client-SKU: MSAL.iOS',
            'Accept: application/json',
            'x-client-OS: 14.3',
            'x-app-name: Grünbeck',
            'x-client-CPU: 64',
            'x-app-ver: 1.2.0',
            'Accept-Language: de-de',
            'client-request-id: F2929DED-2C9D-49F5-A0F4-31215427667C',
            'x-ms-PkeyAuth: 1.0',
            'x-client-Ver: 0.8.0',
            'x-client-DM: iPhone',
            'User-Agent: Gruenbeck/354 CFNetwork/1209 Darwin/20.2.0',
            'return-client-request-id: true'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            $this->logError("Token-Aktualisierung fehlgeschlagen mit Code: $httpCode");
            return false;
        }
        
        $tokenData = json_decode($response, true);
        if (!isset($tokenData['access_token']) || !isset($tokenData['refresh_token'])) {
            $this->logError("Konnte neue Tokens nicht erhalten");
            return false;
        }
        
        $this->accessToken = $tokenData['access_token'];
        $this->refreshToken = $tokenData['refresh_token'];
        
        $this->logDebug("Token-Aktualisierung erfolgreich");
        
        return true;
    }
    
    /**
     * Sendet Parameteraktualisierungen an das Gerät
     * 
     * @param array $data Parameter-Daten
     * @param string $action Optionale Aktion (Standard: parameters)
     * @return bool Erfolg
     */
    public function pushMgParameter($data, $action = null) {
        if (!$this->accessToken || !$this->mgDeviceId) {
            $this->logError("Nicht authentifiziert oder kein Gerät ausgewählt");
            return false;
        }
        
        $method = 'PATCH';
        if ($action) {
            $method = 'POST';
        } else {
            $action = 'parameters';
        }
        
        $url = "https://prod-eu-gruenbeck-api.azurewebsites.net/api/devices/{$this->mgDeviceId}/{$action}?api-version=" . $this->sdVersion;
        $this->logDebug($url);
        $this->logDebug(json_encode($data));
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Host: prod-eu-gruenbeck-api.azurewebsites.net',
            'Content-Type: application/json',
            'Accept: application/json, text/plain, */*',
            'Accept-Language: de-de',
            'User-Agent: ' . $this->userAgent,
            "Authorization: Bearer {$this->accessToken}"
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 400) {
            $this->logError("Fehler beim Senden von Parametern mit Code: $httpCode");
            return false;
        }
        
        return true;
    }
    
    /**
     * Speichert Authentifizierungs-Tokens in einer Datei
     * 
     * @param string $filename Datei zum Speichern der Tokens
     * @return bool Erfolg
     */
    public function saveTokens($filename) {
        if (!$this->accessToken || !$this->refreshToken || !$this->tenant) {
            $this->logError("Keine Tokens zum Speichern vorhanden");
            return false;
        }
        
        $data = [
            'access_token' => $this->accessToken,
            'refresh_token' => $this->refreshToken,
            'tenant' => $this->tenant,
            'expires' => time() + 3500  // Tokens laufen typischerweise nach 1 Stunde ab
        ];
        
        if (file_put_contents($filename, json_encode($data)) === false) {
            $this->logError("Fehler beim Speichern der Tokens in $filename");
            return false;
        }
        
        return true;
    }
    
    /**
     * Lädt Authentifizierungs-Tokens aus einer Datei
     * 
     * @param string $filename Datei zum Laden der Tokens
     * @return bool Erfolg
     */
    public function loadTokens($filename) {
        if (!file_exists($filename)) {
            $this->logError("Token-Datei $filename existiert nicht");
            return false;
        }
        
        $json = file_get_contents($filename);
        if ($json === false) {
            $this->logError("Fehler beim Lesen der Tokens aus $filename");
            return false;
        }
        
        $data = json_decode($json, true);
        if (!isset($data['access_token']) || !isset($data['refresh_token']) || !isset($data['tenant'])) {
            $this->logError("Ungültige Token-Daten in $filename");
            return false;
        }
        
        // Prüfen, ob Tokens abgelaufen sind
        if (isset($data['expires']) && $data['expires'] < time()) {
            $this->logInfo("Tokens sind abgelaufen, Aktualisierung erforderlich");
            $this->accessToken = $data['access_token'];
            $this->refreshToken = $data['refresh_token'];
            $this->tenant = $data['tenant'];
            
            // Token aktualisieren
            if (!$this->startRefreshToken()) {
                $this->logError("Fehler beim Aktualisieren des abgelaufenen Tokens");
                return false;
            }
            
            // Neue Tokens speichern
            $this->saveTokens($filename);
        } else {
            $this->accessToken = $data['access_token'];
            $this->refreshToken = $data['refresh_token'];
            $this->tenant = $data['tenant'];
        }
        
        return true;
    }
    
    /**
     * Ruft Daten vom Gerät in regelmäßigen Abständen ab
     * 
     * Diese Funktion führt eine kontinuierliche Abfrage der Gerätedaten durch
     * und ruft eine Callback-Funktion mit den abgerufenen Daten auf.
     * Sie aktualisiert auch automatisch das Token, wenn es erforderlich ist.
     * 
     * @param int $interval Abfrageintervall in Sekunden
     * @param callable $callback Callback-Funktion zur Verarbeitung der Daten
     * @param bool $once Nur einmal ausführen, dann beenden
     * @return array|null Die abgerufenen Daten bei $once=true, sonst null
     */
    public function getData($interval = 360, $callback = null, $once = false) {
        if (!$this->accessToken || !$this->mgDeviceId) {
            $this->logError("Nicht authentifiziert oder kein Gerät ausgewählt");
            return null;
        }
        
        if ($interval < 360) {
            $this->logInfo("Intervall zu niedrig. Auf 360sec erhöht, um Blocking zu vermeiden.");
            $interval = 360;
        }
        
        $this->logInfo("Starte Polling mit Intervall von {$interval}s");
        
        // Initialer Datenabruf
        $this->logInfo("Initialer Datenabruf");
        $allData = null;
        
        if ($this->enterSD()) {
            $this->refreshSD();
            $deviceData = $this->parseMgInfos();
            $parameterData = $this->parseMgInfos('parameters');
            $waterData = $this->parseMgInfos('measurements/water');
            $saltData = $this->parseMgInfos('measurements/salt');
            
            $allData = [
                'device' => $deviceData,
                'parameters' => $parameterData,
                'water' => $waterData,
                'salt' => $saltData
            ];
            
            if ($callback && is_callable($callback)) {
                $callback($allData);
            }
            
            if ($once) {
                $this->leaveSD(); // Gerät ordnungsgemäß verlassen
                return $allData;
            }
        } else {
            $this->logError("Fehler beim Betreten des SD für initialen Datenabruf");
            if ($once) {
                return null;
            }
        }
        
        // Polling starten
        $lastTokenRefresh = time();
        
        while (true) {
            sleep($interval);
            
            // Token bei Bedarf aktualisieren (alle 50 Minuten)
            if (time() - $lastTokenRefresh > 50 * 60) {
                $this->logInfo("Aktualisiere Access-Token");
                if ($this->startRefreshToken()) {
                    $lastTokenRefresh = time();
                } else {
                    $this->logError("Token-Aktualisierung fehlgeschlagen, versuche erneute Anmeldung");
                    if ($this->login()) {
                        $lastTokenRefresh = time();
                    } else {
                        $this->logError("Anmeldung fehlgeschlagen, stoppe Polling");
                        break;
                    }
                }
            }
            
            // Neue Daten abrufen
            $this->logInfo("Polling für neue Daten");
            if ($this->enterSD()) {
                $this->refreshSD();
                $deviceData = $this->parseMgInfos();
                
                if ($callback && is_callable($callback)) {
                    $callback([
                        'device' => $deviceData
                    ]);
                }
                
                // Gerät verlassen, wenn wir es nicht kontinuierlich überwachen müssen
                $this->leaveSD();
            } else {
                $this->logError("Fehler beim Betreten des SD, versuche erneute Anmeldung");
                if ($this->login()) {
                    $lastTokenRefresh = time();
                } else {
                    $this->logError("Anmeldung fehlgeschlagen, stoppe Polling");
                    break;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Gibt den aktuellen Access-Token zurück
     * 
     * @return string|null Der Access-Token
     */
    public function getAccessToken() {
        return $this->accessToken;
    }
    
    /**
     * Gibt den aktuellen Refresh-Token zurück
     * 
     * @return string|null Der Refresh-Token
     */
    public function getRefreshToken() {
        return $this->refreshToken;
    }
    
    /**
     * Gibt die Geräte-ID zurück
     * 
     * @return string|null Die Geräte-ID
     */
    public function getMgDeviceId() {
        return $this->mgDeviceId;
    }
    
    /**
     * Gibt die Beschreibung für einen Parameter zurück
     * 
     * @param string $key Der Parameter-Schlüssel
     * @return string Die Beschreibung oder der Schlüssel selbst
     */
    public function getDescription($key) {
        return $this->descriptions[$key] ?? $key;
    }
}
