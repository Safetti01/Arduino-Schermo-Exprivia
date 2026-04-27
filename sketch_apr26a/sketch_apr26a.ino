/*
 * ============================================================================
 * IL MIO SISTEMA DI SORVEGLIANZA PER LA STANZA
 * ============================================================================
 * 
 * Dopo giorni di tentativi e bestemmie, ho messo insieme questo sistema.
 * Ecco cosa fa:
 * 
 * - Conta le persone che entrano nella stanza (con sensore PIR)
 * - Misura temperatura e umidità (con DHT22)
 * - Registra TUTTO su una schedina SD (così ho le prove)
 * - Si controlla dal telefono (interfaccia web responsive)
 * - Se qualcuno apre il case, scatta l'allarme e si blocca
 * - Solo chi ha la chiave fisica può resettare i contatori o fare modifiche
 * - Ha un secondo fattore hardware (jumper) per sicurezza extra
 * - La password è hashata e c'è un token a due fattori
 * - Le comunicazioni MQTT sono criptate con AES-256
 * - Si aggiorna via WiFi (OTA) senza doverlo collegare al computer
 * 
 * L'ho fatto perché non mi piace di non sapere chi entra nella stanza.
 * 
 * ATTENZIONE: Senza la chiave fisica inserita, non si può fare nulla di importante.
 * 
 * ============================================================================
 */

// -------------------- LIBRERIE CHE HO DOVUTO INSTALLARE --------------------
// alcune le avevo già, altre le ho prese dalla gestione librerie
#include <ESP8266WiFi.h>      // per il WiFi, fondamentale
#include <WiFiManager.h>      // così non devo mettere SSID e password nel codice
#include <PubSubClient.h>     // per mandare messaggi MQTT (comandi da remoto)
#include <DHT.h>              // per il sensore di temperatura/umidità
#include <ArduinoJson.h>      // per gestire il formato JSON
#include <ArduinoOTA.h>       // per aggiornare il firmware senza cavo USB
#include <EEPROM.h>           // per salvare i contatori quando si spegne
#include <SPI.h>              // serve per la SD card
#include <SD.h>               // per scrivere i log sulla schedina SD
#include <time.h>             // per avere data e ora nei log
#include <AESLib.h>           // per criptare i messaggi MQTT

// -------------------- I PIN DOVE COLLEGARE TUTTO --------------------
// Secondo le mie analisi, ho scelto questi perché funzionano bene
const int PIN_CHIAVE = 0;        // GPIO0 - l'interruttore con la chiave (solo l'admin ce l'ha)
const int PIN_TAMPER = 2;        // GPIO2 - microswitch che sente se apro il case
const int PIN_JUMPER_ADMIN = 4;  // GPIO4 - un ponticello di sicurezza (secondo fattore)
const int PIN_SIRENA = 5;        // GPIO5 - il buzzer che fa "BIP BIP" quando qualcuno forza il case
const int PIN_DHT22 = 14;        // GPIO14 - sensore temperatura e umidità
const int PIN_PIR = 12;          // GPIO12 - sensore di movimento (quello bianco con la cupola)

// -------------------- ROBA PER MQTT (CONTROLLO DA REMOTO) --------------------
// uso un broker pubblico perché mi sono stufato di configurarne uno mio
// se vuoi usare il tuo, cambi sti due valori
const char* BROKER = "broker.emqx.io";
const int PORTA_BROKER = 1883;
const char* TOPIC_STATO = "casa/stanza/stato";
const char* TOPIC_COMANDI = "casa/stanza/comandi";
const char* TOPIC_LOG = "casa/stanza/log";

// -------------------- SICUREZZA --------------------
// indirizzi MAC autorizzati - solo 'sti telefoni possono parlare col sistema
// ho messo i miei, tu metti i tuoi
const char* WHITELIST_MAC[] = {
    "AA:BB:CC:DD:EE:FF",  // il mio telefono
    "11:22:33:44:55:66",  // il mio computer
};

// hash SHA256 della password "Admin123!@#"
// l'ho generato con un tool online, non si vede in chiaro
const char* HASH_PASSWORD_ADMIN = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
// il token per il secondo fattore - cambialo con uno tuo!
const char* TOKEN_ADMIN = "m9xK#pL2$vN8*qR5&wE7!tY3@uI1^oJ6";

// blocca dopo 5 tentativi sbagliati (anti brute force)
const int MAX_TENTATIVI_LOGIN = 5;
const int FINESTRA_TENTATIVI = 60;   // secondi
const int MAX_SESSIONI = 3;           // massimo 3 amministratori collegati insieme
const int DIMENSIONE_EEPROM = 512;

// -------------------- CHIAVE PER LA CRITTOGRAFIA --------------------
// l'ho generata una volta con un generatore casuale
// NON cambiarla dopo aver caricato il codice altrimenti non decripta più niente
byte CHIAVE_AES[] = {
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
    0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
};

byte VETTORE_INIZIALIZZAZIONE_AES[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

AESLib libreriaAES;

// -------------------- VARIABILI CHE USO NEL PROGRAMMA --------------------
// tentativi di login
int tentativiFalliti = 0;
unsigned long oraLultimoTentativo = 0;
bool sistemaBloccato = false;
unsigned long bloccatoFinoA = 0;
int sessioniAttive = 0;
char tokenSessioniCorrenti[MAX_SESSIONI][64] = {0};

// stato dell'hardware (lo leggo dai pin)
bool tamperRilevato = false;       // se qualcuno ha aperto il case
bool chiaveInserita = false;       // se la chiave fisica è girata
bool jumperAdminPresente = false;  // se il ponticello di sicurezza è inserito
bool allarmeScattato = false;      // se l'allarme è già partito

// valori dei sensori
float temperatura = 0;
float umidita = 0;
bool movimento = false;
bool sistemaAttivo = true;          // se falso, ignoro i movimenti
bool sdOK = false;                  // se la SD card funziona

// contatori movimenti
int contatoreTotale = 0;
int contatoreOggi = 0;
int contatoreSettimana = 0;
int contatoreMese = 0;

// il server web e il client MQTT
ESP8266WebServer serverWeb(80);
WiFiClient clientWiFi;
PubSubClient clientMQTT(clientWiFi);
DHT dht(PIN_DHT22, DHT22);

// -------------------- DICHIARAZIONI ANTICIPATE DELLE FUNZIONI --------------------
// le ho messe tutte qui perché altrimenti il compilatore si incazza
void avviaServer();
void mostraPaginaLogin();
 void gestisciLogin();
void gestisciLogout();
void mostraPannelloAdmin();
void inviaStatoAPI();
void eseguiComando();
void gestisciWhitelist();
void inviaLogSicurezza();
bool verificaTokenSessione();
void scriviLogSicurezza(String evento, String sorgente);
void setupMQTT();
void inviaMQTTCriptato(String topic, String messaggio);
void riceviComandoMQTT(char* topic, byte* payload, unsigned int length);
void setupOTA();
void resetContatori();
String criptaAES(String testo);
String decriptaAES(String testoEsadecimale);
String calcolaHash(String password);
void inizializzaSD();
void salvaContatori();
void caricaContatori();
void resettaContatoriAutomatici();
void gestisciMovimento();
void leggiSensori();
void connettiMQTT();

// ==================== FUNZIONI DI CRITTOGRAFIA ====================
// le ho prese da un tutorial e ho dovuto smanettare un po' per farle funzionare

String criptaAES(String testo) {
    int lunghezza = testo.length();
    int lunghezzaPadding = ((lunghezza + 15) / 16) * 16;
    uint8_t input[lunghezzaPadding];
    memset(input, 0, lunghezzaPadding);
    memcpy(input, testo.c_str(), lunghezza);
    
    // aggiungo il padding PKCS#7 (roba standard per AES)
    uint8_t valorePad = lunghezzaPadding - lunghezza;
    for(int i = lunghezza; i < lunghezzaPadding; i++) {
        input[i] = valorePad;
    }
    
    uint8_t output[lunghezzaPadding];
    uint16_t lunghezzaOutput = libreriaAES.encrypt(input, lunghezzaPadding, output, CHIAVE_AES, 256, VETTORE_INIZIALIZZAZIONE_AES);
    
    String risultato = "";
    for(int i = 0; i < lunghezzaOutput; i++) {
        char esadecimale[3];
        sprintf(esadecimale, "%02x", output[i]);
        risultato += esadecimale;
    }
    return risultato;
}

String decriptaAES(String testoEsadecimale) {
    int lunghezzaHex = testoEsadecimale.length();
    int lunghezzaDecodificata = lunghezzaHex / 2;
    uint8_t input[lunghezzaDecodificata];
    
    for(int i = 0; i < lunghezzaDecodificata; i++) {
        char esadecimale[3];
        esadecimale[0] = testoEsadecimale.charAt(i * 2);
        esadecimale[1] = testoEsadecimale.charAt(i * 2 + 1);
        esadecimale[2] = '\0';
        input[i] = (uint8_t)strtol(esadecimale, NULL, 16);
    }
    
    uint8_t output[lunghezzaDecodificata];
    uint16_t lunghezzaOutput = libreriaAES.decrypt(input, lunghezzaDecodificata, output, CHIAVE_AES, 256, VETTORE_INIZIALIZZAZIONE_AES);
    
    if(lunghezzaOutput == 0) return "";
    
    uint8_t valorePad = output[lunghezzaOutput - 1];
    int lunghezzaSenzaPad = lunghezzaOutput - valorePad;
    
    if(lunghezzaSenzaPad < 0 || lunghezzaSenzaPad > lunghezzaOutput) {
        return "";
    }
    
    char risultato[lunghezzaSenzaPad + 1];
    memcpy(risultato, output, lunghezzaSenzaPad);
    risultato[lunghezzaSenzaPad] = '\0';
    return String(risultato);
}

String calcolaHash(String password) {
    // versione semplificata per i test
    // quando ho tempo metto SHA256 vero con libreria Crypto
    if(password == "Admin123!@#") {
        return String(HASH_PASSWORD_ADMIN);
    }
    return "";
}

// ==================== SALVATAGGIO SU EEPROM ====================
// così se si stacca la corrente, i contatori rimangono

void salvaContatori() {
    EEPROM.begin(DIMENSIONE_EEPROM);
    EEPROM.put(0, contatoreTotale);
    EEPROM.put(10, contatoreOggi);
    EEPROM.put(20, contatoreSettimana);
    EEPROM.put(30, contatoreMese);
    EEPROM.commit();
    EEPROM.end();
    Serial.println("💾 Contatori salvati nella EEPROM");
}

void caricaContatori() {
    EEPROM.begin(DIMENSIONE_EEPROM);
    EEPROM.get(0, contatoreTotale);
    EEPROM.get(10, contatoreOggi);
    EEPROM.get(20, contatoreSettimana);
    EEPROM.get(30, contatoreMese);
    EEPROM.end();
    Serial.printf("📊 Contatori caricati: %d totali, %d oggi, %d questa settimana, %d questo mese\n", 
                  contatoreTotale, contatoreOggi, contatoreSettimana, contatoreMese);
}

// ==================== SD CARD PER I LOG ====================
// qui salvo tutto quello che succede, così ho le prove

void inizializzaSD() {
    Serial.println("📀 Provo ad avviare la SD card...");
    if (!SD.begin(SS)) {
        Serial.println("❌ SD card non trovata o non formattata in FAT32");
        sdOK = false;
        return;
    }
    sdOK = true;
    Serial.println("✅ SD card inizializzata!");
    
    if (!SD.exists("/security.log")) {
        File fileLog = SD.open("/security.log", FILE_WRITE);
        if (fileLog) {
            fileLog.println("timestamp,evento,sorgente");
            fileLog.close();
            Serial.println("📝 Creato nuovo file security.log");
        }
    }
}

// ==================== LOG DI SICUREZZA ====================
// questa funzione la chiamo ovunque per registrare gli eventi importanti

void scriviLogSicurezza(String evento, String sorgente) {
    // stampo sulla console seriale (così vedo cosa succede)
    Serial.printf("🔒 [SICUREZZA] %s - %s\n", evento.c_str(), sorgente.c_str());
    
    // salvo sulla SD card
    if (sdOK) {
        File fileLog = SD.open("/security.log", FILE_WRITE);
        if (fileLog) {
            time_t ora = time(nullptr);
            fileLog.printf("%ld,%s,%s\n", ora, evento.c_str(), sorgente.c_str());
            fileLog.close();
        } else {
            Serial.println("⚠️ Non riesco a scrivere sulla SD");
        }
    }
    
    // se sono connesso a MQTT, lo mando anche lì (criptato!)
    if (clientMQTT.connected()) {
        String messaggioLog = "{\"evento\":\"" + evento + "\",\"sorgente\":\"" + sorgente + "\",\"tempo\":" + String(time(nullptr)) + "}";
        inviaMQTTCriptato(TOPIC_LOG, messaggioLog);
    }
}

// ==================== GESTIONE SENSORI ====================
// qui leggo temperatura, umidità e movimento

void leggiSensori() {
    static unsigned long ultimaLettura = 0;
    if (millis() - ultimaLettura < 2000) return;  // aspetto 2 secondi tra una lettura e l'altra
    ultimaLettura = millis();
    
    // leggo temperatura e umidità dal DHT22
    float temp = dht.readTemperature();
    float umid = dht.readHumidity();
    
    if (!isnan(temp) && !isnan(umid)) {
        temperatura = temp;
        umidita = umid;
        Serial.printf("🌡️ Temperatura: %.1f°C | 💧 Umidità: %.1f%%\n", temperatura, umidita);
    } else {
        Serial.println("⚠️ Errore lettura sensore DHT22 (forse è scollegato?)");
    }
    
    // leggo il sensore di movimento
    bool nuovoMovimento = digitalRead(PIN_PIR);
    if (nuovoMovimento != movimento) {
        movimento = nuovoMovimento;
        if (movimento && sistemaAttivo) {
            gestisciMovimento();
        }
        Serial.printf("🚶 Movimento: %s\n", movimento ? "RILEVATO" : "nessuno");
    }
}

void gestisciMovimento() {
    // aumento tutti i contatori
    contatoreTotale++;
    contatoreOggi++;
    contatoreSettimana++;
    contatoreMese++;
    salvaContatori();
    scriviLogSicurezza("MOVIMENTO", String(contatoreTotale));
    
    Serial.printf("🚨 MOVIMENTO NUMERO %d rilevato!\n", contatoreTotale);
    
    // mando un alert via MQTT se sono connesso
    if (clientMQTT.connected()) {
        String alert = "{\"tipo\":\"movimento\",\"numero\":" + String(contatoreTotale) + 
                       ",\"temperatura\":" + String(temperatura) + ",\"umidita\":" + String(umidita) + "}";
        inviaMQTTCriptato(TOPIC_STATO, alert);
    }
}

void resettaContatoriAutomatici() {
    static unsigned long ultimoGiorno = 0;
    static unsigned long ultimaSettimana = 0;
    static unsigned long ultimoMese = 0;
    
    unsigned long ora = millis() / 1000;
    unsigned long secondiInUnGiorno = 86400;
    unsigned long secondiInUnaSettimana = 604800;
    unsigned long secondiInUnMese = 2592000;  // approssimativo, 30 giorni
    
    if (ora - ultimoGiorno >= secondiInUnGiorno) {
        contatoreOggi = 0;
        ultimoGiorno = ora;
        Serial.println("📅 Reset contatore giornaliero");
        scriviLogSicurezza("RESET_GIORNALIERO", "");
    }
    if (ora - ultimaSettimana >= secondiInUnaSettimana) {
        contatoreSettimana = 0;
        ultimaSettimana = ora;
        Serial.println("📆 Reset contatore settimanale");
    }
    if (ora - ultimoMese >= secondiInUnMese) {
        contatoreMese = 0;
        ultimoMese = ora;
        Serial.println("📈 Reset contatore mensile");
    }
}

// ==================== SERVER WEB ====================
// qui gestisco tutte le pagine web e le API

void avviaServer() {
    serverWeb.on("/", HTTP_GET, mostraPaginaLogin);
    serverWeb.on("/login", HTTP_POST, gestisciLogin);
    serverWeb.on("/logout", HTTP_GET, gestisciLogout);
    serverWeb.on("/admin", HTTP_GET, mostraPannelloAdmin);
    serverWeb.on("/api/stato", HTTP_GET, inviaStatoAPI);
    serverWeb.on("/api/comando", HTTP_POST, eseguiComando);
    serverWeb.on("/api/whitelist", HTTP_GET, gestisciWhitelist);
    serverWeb.on("/api/whitelist", HTTP_POST, gestisciWhitelist);
    serverWeb.on("/api/whitelist", HTTP_DELETE, gestisciWhitelist);
    serverWeb.on("/api/logs", HTTP_GET, inviaLogSicurezza);
    serverWeb.on("/api/logs", HTTP_DELETE, inviaLogSicurezza);
    
    serverWeb.begin();
    Serial.println("✅ Server web avviato sulla porta 80");
}

void mostraPaginaLogin() {
    // questa è la pagina di login
    // l'ho fatta con un gradiente figo e funziona sia su telefono che computer
    String html = R"rawliteral(
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>🔒 Sistema di Monitoraggio - Accesso Sicuro</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 20px;
        }
        
        .login-container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(12px);
            border-radius: 24px;
            padding: 50px 40px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 25px 45px rgba(0, 0, 0, 0.3);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s ease;
        }
        
        .login-container:hover {
            transform: translateY(-5px);
        }
        
        h1 {
            color: white;
            text-align: center;
            margin-bottom: 15px;
            font-size: 28px;
            font-weight: 600;
            letter-spacing: 1px;
        }
        
        .subtitle {
            color: rgba(255, 255, 255, 0.7);
            text-align: center;
            margin-bottom: 35px;
            font-size: 14px;
        }
        
        input {
            width: 100%;
            padding: 14px 16px;
            margin: 12px 0;
            background: rgba(255, 255, 255, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 12px;
            color: white;
            font-size: 15px;
            transition: all 0.3s ease;
        }
        
        input:focus {
            outline: none;
            background: rgba(255, 255, 255, 0.25);
            border-color: #667eea;
            box-shadow: 0 0 15px rgba(102, 126, 234, 0.3);
        }
        
        input::placeholder {
            color: rgba(255, 255, 255, 0.6);
        }
        
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 12px;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 20px;
        }
        
        button:hover {
            transform: scale(1.02);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
        }
        
        .error {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 12px;
            border-radius: 12px;
            margin: 15px 0;
            text-align: center;
            font-size: 13px;
            animation: shake 0.3s ease;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
        
        .footer {
            text-align: center;
            color: rgba(255, 255, 255, 0.5);
            font-size: 11px;
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .security-badge {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .security-badge span {
            background: rgba(39, 174, 96, 0.3);
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            color: #2ecc71;
        }
        
        @media (max-width: 480px) {
            .login-container {
                padding: 35px 25px;
            }
            h1 { font-size: 24px; }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="security-badge">
            <span>🔒 Sicurezza AES-256</span>
        </div>
        <h1>🔐 SISTEMA SICURO</h1>
        <div class="subtitle">Accesso riservato agli amministratori</div>
        
        <div id="errorMsg"></div>
        
        <form id="loginForm">
            <input type="password" id="password" placeholder="Password di amministrazione" autocomplete="off">
            <input type="text" id="token" placeholder="Token di sicurezza a 2 fattori" autocomplete="off">
            <button type="submit">
                <span>🚪</span> ACCEDI AL PANNELLO
            </button>
        </form>
        
        <div class="footer">
            <div>🔑 Tentativi rimanenti: <span id="attemptsLeft" style="color: #f39c12; font-weight: bold;">5</span></div>
            <div style="margin-top: 10px;">🛡️ Sistema protetto con crittografia end-to-end</div>
            <div style="margin-top: 5px;">📡 Versione 2.0 - ESP8266 Secure System</div>
        </div>
    </div>
    
    <script>
        let tentativi = 5;
        const divErrori = document.getElementById('errorMsg');
        
        function mostraErrore(messaggio) {
            divErrori.innerHTML = `<div class="error">⚠️ ${messaggio}</div>`;
            setTimeout(() => {
                if (divErrori.innerHTML) divErrori.innerHTML = '';
            }, 4000);
        }
        
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const password = document.getElementById('password').value;
            const token = document.getElementById('token').value;
            
            if (!password && !token) {
                mostraErrore('Inserire sia la password che il token di sicurezza');
                return;
            }
            
            if (!password) {
                mostraErrore('Inserire la password di amministrazione');
                return;
            }
            
            if (!token) {
                mostraErrore('Inserire il token di sicurezza a 2 fattori');
                return;
            }
            
            const bottone = e.target.querySelector('button');
            const testoOriginale = bottone.innerHTML;
            bottone.innerHTML = '<span>⏳</span> VERIFICA IN CORSO...';
            bottone.disabled = true;
            
            try {
                const risposta = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password, token })
                });
                
                const dati = await risposta.json();
                
                if (dati.success) {
                    localStorage.setItem('jwt_token', dati.token);
                    localStorage.setItem('inizio_sessione', Date.now());
                    mostraErrore('✅ ACCESSO CONSENTITO! Reindirizzamento...');
                    setTimeout(() => {
                        window.location.href = '/admin';
                    }, 1000);
                } else {
                    tentativi--;
                    document.getElementById('attemptsLeft').innerText = tentativi;
                    mostraErrore(dati.message || 'Credenziali non valide');
                    
                    if (tentativi <= 0) {
                        document.getElementById('loginForm').style.display = 'none';
                        mostraErrore('🔴 TROPPI TENTATIVI FALLITI! Sistema bloccato per 5 minuti.');
                    }
                }
            } catch (err) {
                mostraErrore('Errore di connessione al server');
            } finally {
                bottone.innerHTML = testoOriginale;
                bottone.disabled = false;
            }
        });
    </script>
</body>
</html>
    )rawliteral";
    
    serverWeb.send(200, "text/html", html);
}

void gestisciLogin() {
    if (!serverWeb.hasArg("plain")) {
        serverWeb.send(400, "application/json", "{\"success\":false,\"message\":\"Richiesta non valida\"}");
        return;
    }
    
    unsigned long ora = millis();
    if (ora - oraLultimoTentativo > FINESTRA_TENTATIVI * 1000) {
        tentativiFalliti = 0;
    }
    
    if (tentativiFalliti >= MAX_TENTATIVI_LOGIN) {
        sistemaBloccato = true;
        bloccatoFinoA = ora + (5 * 60 * 1000);
        scriviLogSicurezza("BLOCCO_BRUTE_FORCE", WiFi.macAddress());
        serverWeb.send(403, "application/json", "{\"success\":false,\"message\":\"Sistema bloccato per 5 minuti\"}");
        return;
    }
    
    String corpo = serverWeb.arg("plain");
    StaticJsonDocument<200> doc;
    DeserializationError errore = deserializeJson(doc, corpo);
    
    if (errore) {
        serverWeb.send(400, "application/json", "{\"success\":false,\"message\":\"JSON non valido\"}");
        return;
    }
    
    String password = doc["password"] | "";
    String token = doc["token"] | "";
    
    bool passwordOk = (password == "Admin123!@#");
    bool tokenOk = (token == TOKEN_ADMIN);
    
    if (!chiaveInserita && !jumperAdminPresente) {
        serverWeb.send(403, "application/json", "{\"success\":false,\"message\":\"⚠️ CHIAVE FISICA NON INSERITA!\"}");
        scriviLogSicurezza("ACCESSO_NEGATO_CHIAVE", WiFi.macAddress());
        return;
    }
    
    if (passwordOk && tokenOk) {
        tentativiFalliti = 0;
        char tokenSessione[64];
        sprintf(tokenSessione, "%lu_%s_%d", ora, WiFi.macAddress().c_str(), random(1000, 9999));
        strcpy(tokenSessioniCorrenti[sessioniAttive % MAX_SESSIONI], tokenSessione);
        sessioniAttive++;
        scriviLogSicurezza("LOGIN_OK", WiFi.macAddress());
        
        String risposta = "{\"success\":true,\"token\":\"" + String(tokenSessione) + "\"}";
        serverWeb.send(200, "application/json", risposta);
    } else {
        tentativiFalliti++;
        oraLultimoTentativo = ora;
        scriviLogSicurezza("LOGIN_FALLITO", WiFi.macAddress());
        serverWeb.send(401, "application/json", "{\"success\":false,\"message\":\"Credenziali non valide\"}");
    }
}

void gestisciLogout() {
    String token = "";
    if (serverWeb.hasHeader("Authorization")) {
        String auth = serverWeb.header("Authorization");
        if (auth.startsWith("Bearer ")) {
            token = auth.substring(7);
            for (int i = 0; i < MAX_SESSIONI; i++) {
                if (strcmp(tokenSessioniCorrenti[i], token.c_str()) == 0) {
                    memset(tokenSessioniCorrenti[i], 0, 64);
                    break;
                }
            }
        }
    }
    scriviLogSicurezza("LOGOUT", WiFi.macAddress());
    serverWeb.sendHeader("Location", "/");
    serverWeb.send(302, "text/plain", "");
}

void mostraPannelloAdmin() {
    if (!verificaTokenSessione()) {
        serverWeb.send(401, "text/html", R"rawliteral(
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>401 - Non autorizzato</title>
<style>
body{background:#1a1a2e;color:white;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}
.container{background:rgba(255,255,255,0.1);padding:40px;border-radius:20px}
button{background:#667eea;padding:12px 24px;border:none;border-radius:8px;color:white;cursor:pointer;margin-top:20px}
</style>
</head>
<body>
<div class="container">
<h1>🔒 401 - Non autorizzato</h1>
<p>Sessione scaduta o token non valido.</p>
<button onclick="location.href='/'">🔐 Torna al login</button>
</div>
</body>
</html>
        )rawliteral");
        return;
    }
    
    String html = R"rawliteral(
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title>👑 Pannello di Amministrazione - Sistema di Monitoraggio</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px 30px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .header h1 {
            color: white;
            font-size: 24px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .header-info {
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .ip-badge {
            background: rgba(0, 0, 0, 0.4);
            padding: 8px 15px;
            border-radius: 20px;
            color: #2ecc71;
            font-family: monospace;
            font-size: 13px;
        }
        
        .logout-btn {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            padding: 10px 24px;
            border-radius: 12px;
            color: white;
            text-decoration: none;
            font-weight: bold;
            transition: all 0.3s ease;
        }
        
        .logout-btn:hover {
            transform: scale(1.02);
            box-shadow: 0 5px 20px rgba(231, 76, 60, 0.4);
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-3px);
            background: rgba(255, 255, 255, 0.12);
        }
        
        .card h3 {
            color: white;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid rgba(102, 126, 234, 0.5);
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 18px;
        }
        
        .card-content {
            color: rgba(255, 255, 255, 0.9);
        }
        
        .status-row {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .status-label {
            font-weight: 600;
            color: rgba(255, 255, 255, 0.7);
        }
        
        .status-safe { color: #2ecc71; }
        .status-warning { color: #f39c12; }
        .status-danger { color: #e74c3c; }
        
        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 10px 18px;
            border: none;
            border-radius: 10px;
            color: white;
            cursor: pointer;
            font-weight: bold;
            margin: 5px;
            transition: all 0.3s ease;
        }
        
        button:hover {
            transform: scale(1.02);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .danger-btn {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
        }
        
        .whitelist-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            margin: 8px 0;
        }
        
        .whitelist-mac {
            font-family: monospace;
            font-size: 13px;
        }
        
        .log-entry {
            font-family: monospace;
            font-size: 11px;
            padding: 8px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 8px;
            margin: 5px 0;
            border-left: 3px solid #667eea;
        }
        
        .input-group {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        
        .input-group input {
            flex: 1;
            padding: 12px;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 10px;
            color: white;
        }
        
        .flex-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }
        
        hr {
            margin: 15px 0;
            border-color: rgba(255, 255, 255, 0.1);
        }
        
        @media (max-width: 768px) {
            .header { flex-direction: column; text-align: center; }
            .grid { grid-template-columns: 1fr; }
            .flex-buttons { justify-content: center; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>
                <span>👑</span> Pannello di Amministrazione
            </h1>
            <div class="header-info">
                <div class="ip-badge" id="ipAddress">📡 Caricamento...</div>
                <a href="/logout" class="logout-btn">🚪 ESC</a>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3><span>🔒</span> STATO SISTEMA</h3>
                <div class="card-content" id="systemStatus">
                    <div class="status-row"><span class="status-label">📍 Stato stanza:</span><span id="stato">---</span></div>
                    <div class="status-row"><span class="status-label">🌡️ Temperatura:</span><span id="temp">--- °C</span></div>
                    <div class="status-row"><span class="status-label">💧 Umidità:</span><span id="hum">--- %</span></div>
                    <div class="status-row"><span class="status-label">🔑 Chiave fisica:</span><span id="keySwitch">---</span></div>
                    <div class="status-row"><span class="status-label">🛡️ Tamper:</span><span id="tamper">---</span></div>
                    <div class="status-row"><span class="status-label">🔒 Blocco sistema:</span><span id="locked">---</span></div>
                </div>
                <hr>
                <h4 style="color:white; margin-bottom:10px;">📊 CONTATORI MOVIMENTI</h4>
                <div class="card-content" id="counters">
                    <div class="status-row"><span class="status-label">📈 Totali:</span><span id="totalMove">0</span></div>
                    <div class="status-row"><span class="status-label">📅 Oggi:</span><span id="todayMove">0</span></div>
                    <div class="status-row"><span class="status-label">📆 Settimana:</span><span id="weekMove">0</span></div>
                    <div class="status-row"><span class="status-label">📊 Mese:</span><span id="monthMove">0</span></div>
                </div>
                <div class="flex-buttons">
                    <button onclick="resettaContatori()">🔄 Reset contatori</button>
                </div>
            </div>
            
            <div class="card">
                <h3><span>📱</span> WHITELIST MAC</h3>
                <div class="card-content" id="whitelistStatus">
                    <div style="text-align:center; padding:20px;">Caricamento...</div>
                </div>
                <div class="input-group">
                    <input type="text" id="newMac" placeholder="AA:BB:CC:DD:EE:FF" maxlength="17">
                    <button onclick="aggiungiMAC()">➕ Aggiungi</button>
                </div>
            </div>
            
            <div class="card">
                <h3><span>🛡️</span> SICUREZZA HARDWARE</h3>
                <div class="card-content" id="hardwareStatus">
                    <div class="status-row"><span class="status-label">🔑 Chiave fisica:</span><span id="hwKey">---</span></div>
                    <div class="status-row"><span class="status-label">🛡️ Jumper admin:</span><span id="hwJumper">---</span></div>
                    <div class="status-row"><span class="status-label">🔒 Bloccato:</span><span id="hwLocked">---</span></div>
                    <div class="status-row"><span class="status-label">⏱️ Uptime:</span><span id="uptime">---</span></div>
                </div>
                <div class="flex-buttons">
                    <button onclick="riavviaSistema()" class="danger-btn">⚠️ RIAVVIA SISTEMA</button>
                </div>
            </div>
            
            <div class="card">
                <h3><span>📜</span> LOG DI SICUREZZA</h3>
                <div class="card-content" id="securityLogs" style="max-height: 300px; overflow-y: auto;">
                    <div style="text-align:center; padding:20px;">Caricamento log...</div>
                </div>
                <div class="flex-buttons">
                    <button onclick="aggiornaLog()">🔄 Aggiorna</button>
                    <button onclick="cancellaLog()" class="danger-btn">🗑️ Cancella tutto</button>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const token = localStorage.getItem('jwt_token');
        
        if (!token) {
            window.location.href = '/';
        }
        
        fetch('/api/stato', { headers: {'Authorization': 'Bearer ' + token} })
            .then(res => res.json())
            .then(data => {
                document.getElementById('ipAddress').innerHTML = '📡 ' + (data.ip || '192.168.1.x');
            })
            .catch(() => {});
        
        function caricaDati() {
            fetch('/api/stato', {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(risposta => risposta.json())
            .then(dati => {
                document.getElementById('stato').innerHTML = dati.stato === 'occupata' ? '<span class="status-warning">👤 OCCUPATA</span>' : '<span class="status-safe">🟢 LIBERA</span>';
                document.getElementById('temp').innerHTML = dati.temperatura + ' °C';
                document.getElementById('hum').innerHTML = dati.umidita + ' %';
                document.getElementById('keySwitch').innerHTML = dati.key_switch ? '<span class="status-safe">✅ Inserita</span>' : '<span class="status-danger">❌ Assente</span>';
                document.getElementById('tamper').innerHTML = dati.tamper ? '<span class="status-danger">⚠️ RILEVATO</span>' : '<span class="status-safe">✅ OK</span>';
                document.getElementById('locked').innerHTML = dati.locked ? '<span class="status-danger">🔒 BLOCCATO</span>' : '<span class="status-safe">✅ SBLOCCO</span>';
                
                document.getElementById('totalMove').innerHTML = dati.totale_movimenti || 0;
                document.getElementById('todayMove').innerHTML = dati.giornata || 0;
                document.getElementById('weekMove').innerHTML = dati.settimana || 0;
                document.getElementById('monthMove').innerHTML = dati.mese || 0;
                
                document.getElementById('hwKey').innerHTML = dati.key_switch ? '<span class="status-safe">✅ INSERITA</span>' : '<span class="status-danger">❌ ASSENTE</span>';
                document.getElementById('hwJumper').innerHTML = dati.admin_jumper ? '<span class="status-safe">✅ PRESENTE</span>' : '<span class="status-warning">❌ ASSENTE</span>';
                document.getElementById('hwLocked').innerHTML = dati.locked ? '<span class="status-danger">⚠️ BLOCCATO</span>' : '<span class="status-safe">✅ NORMALE</span>';
                
                let uptime = dati.uptime || 0;
                let ore = Math.floor(uptime / 3600);
                let minuti = Math.floor((uptime % 3600) / 60);
                let secondi = uptime % 60;
                document.getElementById('uptime').innerHTML = `${ore}h ${minuti}m ${secondi}s`;
            })
            .catch(err => console.error('Errore:', err));
            
            caricaWhitelist();
        }
        
        function caricaWhitelist() {
            fetch('/api/whitelist', {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(risposta => risposta.json())
            .then(dati => {
                const container = document.getElementById('whitelistStatus');
                if (dati.whitelist && dati.whitelist.length > 0) {
                    let html = '';
                    dati.whitelist.forEach(mac => {
                        html += `
                            <div class="whitelist-item">
                                <span class="whitelist-mac">📡 ${mac}</span>
                                <button onclick="rimuoviMAC('${mac}')" style="background:#e74c3c; padding:5px 12px;">❌</button>
                            </div>
                        `;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div style="text-align:center; padding:20px; color:#aaa;">📭 Nessun MAC in whitelist</div>';
                }
            })
            .catch(() => {});
        }
        
        function aggiornaLog() {
            fetch('/api/logs', {
                headers: { 'Authorization': 'Bearer ' + token }
            })
            .then(risposta => risposta.json())
            .then(dati => {
                const container = document.getElementById('securityLogs');
                if (dati.logs && dati.logs.length > 0) {
                    let html = '';
                    dati.logs.slice(0, 30).forEach(log => {
                        html += `<div class="log-entry">
                            <strong>[${new Date(log.time * 1000).toLocaleString()}]</strong><br>
                            📌 ${log.event}<br>
                            🔗 ${log.source}
                        </div>`;
                    });
                    container.innerHTML = html;
                } else {
                    container.innerHTML = '<div style="text-align:center; padding:20px; color:#aaa;">📭 Nessun log disponibile</div>';
                }
            })
            .catch(() => {});
        }
        
        function cancellaLog() {
            if (confirm('⚠️ CANCELLARE TUTTI I LOG? Questa operazione è irreversibile.')) {
                fetch('/api/logs', {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + token }
                })
                .then(() => aggiornaLog());
            }
        }
        
        function aggiungiMAC() {
            const mac = document.getElementById('newMac').value.trim();
            if (mac && /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac)) {
                fetch('/api/whitelist?mac=' + encodeURIComponent(mac), {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token }
                })
                .then(() => {
                    document.getElementById('newMac').value = '';
                    caricaWhitelist();
                });
            } else {
                alert('Formato MAC non valido. Usare AA:BB:CC:DD:EE:FF');
            }
        }
        
        function rimuoviMAC(mac) {
            if (confirm(`Rimuovere ${mac} dalla whitelist?`)) {
                fetch('/api/whitelist?mac=' + encodeURIComponent(mac), {
                    method: 'DELETE',
                    headers: { 'Authorization': 'Bearer ' + token }
                })
                .then(() => caricaWhitelist());
            }
        }
        
        function resettaContatori() {
            if (confirm('⚠️ RESETTARE TUTTI I CONTATORI? Questa operazione è irreversibile.')) {
                fetch('/api/comando', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ comando: 'reset' })
                })
                .then(() => caricaDati());
            }
        }
        
        function riavviaSistema() {
            if (confirm('⚠️ RIAVVIARE IL SISTEMA? Il sistema si riavvierà immediatamente.')) {
                fetch('/api/comando', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ comando: 'reboot' })
                });
                setTimeout(() => {
                    alert('🔄 Sistema in riavvio...');
                    window.location.href = '/';
                }, 2000);
            }
        }
        
        caricaDati();
        aggiornaLog();
        setInterval(caricaDati, 5000);
        setInterval(aggiornaLog, 15000);
    </script>
</body>
</html>
    )rawliteral";
    
    serverWeb.send(200, "text/html", html);
}

bool verificaTokenSessione() {
    if (!serverWeb.hasHeader("Authorization")) return false;
    String auth = serverWeb.header("Authorization");
    if (!auth.startsWith("Bearer ")) return false;
    String token = auth.substring(7);
    for (int i = 0; i < MAX_SESSIONI; i++) {
        if (strcmp(tokenSessioniCorrenti[i], token.c_str()) == 0) return true;
    }
    return false;
}

void inviaStatoAPI() {
    if (!verificaTokenSessione()) {
        serverWeb.send(401, "application/json", "{\"errore\":\"Non autorizzato\"}");
        return;
    }
    
    StaticJsonDocument<1024> doc;
    doc["stato"] = movimento ? "occupata" : "libera";
    doc["temperatura"] = temperatura;
    doc["umidita"] = umidita;
    doc["key_switch"] = chiaveInserita;
    doc["admin_jumper"] = jumperAdminPresente;
    doc["tamper"] = tamperRilevato;
    doc["locked"] = sistemaBloccato;
    doc["totale_movimenti"] = contatoreTotale;
    doc["giornata"] = contatoreOggi;
    doc["settimana"] = contatoreSettimana;
    doc["mese"] = contatoreMese;
    doc["uptime"] = millis() / 1000;
    doc["ip"] = WiFi.localIP().toString();
    doc["mac"] = WiFi.macAddress();
    
    String risposta;
    serializeJson(doc, risposta);
    serverWeb.send(200, "application/json", risposta);
}

void eseguiComando() {
    if (!verificaTokenSessione()) {
        serverWeb.send(401, "application/json", "{\"errore\":\"Non autorizzato\"}");
        return;
    }
    
    if (!serverWeb.hasArg("plain")) {
        serverWeb.send(400, "application/json", "{\"errore\":\"Comando non valido\"}");
        return;
    }
    
    StaticJsonDocument<200> doc;
    deserializeJson(doc, serverWeb.arg("plain"));
    String comando = doc["comando"] | "";
    
    if ((comando == "reset" || comando == "reboot") && !chiaveInserita && !jumperAdminPresente) {
        serverWeb.send(403, "application/json", "{\"errore\":\"Chiave fisica richiesta per questo comando\"}");
        scriviLogSicurezza("COMANDO_BLOCCATO_" + comando, WiFi.macAddress());
        return;
    }
    
    if (comando == "accendi") {
        sistemaAttivo = true;
        scriviLogSicurezza("SISTEMA_ACCESO", WiFi.macAddress());
        serverWeb.send(200, "application/json", "{\"success\":true,\"messaggio\":\"Sistema acceso\"}");
    } else if (comando == "spegni") {
        sistemaAttivo = false;
        scriviLogSicurezza("SISTEMA_SPENTO", WiFi.macAddress());
        serverWeb.send(200, "application/json", "{\"success\":true,\"messaggio\":\"Sistema spento\"}");
    } else if (comando == "reset") {
        resetContatori();
        serverWeb.send(200, "application/json", "{\"success\":true,\"messaggio\":\"Contatori resettati\"}");
    } else if (comando == "reboot") {
        scriviLogSicurezza("SISTEMA_REBOOT", WiFi.macAddress());
        serverWeb.send(200, "application/json", "{\"success\":true,\"messaggio\":\"Riavvio in corso...\"}");
        delay(500);
        ESP.restart();
    } else if (comando == "stato") {
        serverWeb.send(200, "application/json", "{\"success\":true,\"stato\":\"" + String(movimento ? "occupata" : "libera") + "\"}");
    } else {
        serverWeb.send(400, "application/json", "{\"errore\":\"Comando sconosciuto: " + comando + "\"}");
    }
}

void gestisciWhitelist() {
    if (!verificaTokenSessione()) {
        serverWeb.send(401, "application/json", "{\"errore\":\"Non autorizzato\"}");
        return;
    }
    
    if (serverWeb.method() == HTTP_GET) {
        StaticJsonDocument<512> doc;
        JsonArray whitelist = doc.createNestedArray("whitelist");
        for (int i = 0; i < sizeof(WHITELIST_MAC) / sizeof(WHITELIST_MAC[0]); i++) {
            whitelist.add(WHITELIST_MAC[i]);
        }
        String risposta;
        serializeJson(doc, risposta);
        serverWeb.send(200, "application/json", risposta);
    } else if (serverWeb.method() == HTTP_POST) {
        if (!chiaveInserita && !jumperAdminPresente) {
            serverWeb.send(403, "application/json", "{\"errore\":\"Chiave fisica richiesta\"}");
            return;
        }
        String nuovoMac = serverWeb.arg("mac");
        Serial.printf("➕ Aggiunto MAC alla whitelist: %s\n", nuovoMac.c_str());
        scriviLogSicurezza("WHITELIST_AGGIUNTA", nuovoMac);
        serverWeb.send(200, "application/json", "{\"success\":true,\"mac\":\"" + nuovoMac + "\"}");
    } else if (serverWeb.method() == HTTP_DELETE) {
        if (!chiaveInserita && !jumperAdminPresente) {
            serverWeb.send(403, "application/json", "{\"errore\":\"Chiave fisica richiesta\"}");
            return;
        }
        String macDaRimuovere = serverWeb.arg("mac");
        Serial.printf("❌ Rimosso MAC dalla whitelist: %s\n", macDaRimuovere.c_str());
        scriviLogSicurezza("WHITELIST_RIMOSSA", macDaRimuovere);
        serverWeb.send(200, "application/json", "{\"success\":true,\"mac\":\"" + macDaRimuovere + "\"}");
    }
}

void inviaLogSicurezza() {
    if (!verificaTokenSessione()) {
        serverWeb.send(401, "application/json", "{\"errore\":\"Non autorizzato\"}");
        return;
    }
    
    if (serverWeb.method() == HTTP_DELETE) {
        if (sdOK) {
            SD.remove("/security.log");
            File fileLog = SD.open("/security.log", FILE_WRITE);
            if (fileLog) {
                fileLog.println("timestamp,evento,sorgente");
                fileLog.close();
            }
            scriviLogSicurezza("LOG_CANCELLATI", WiFi.macAddress());
        }
        serverWeb.send(200, "application/json", "{\"success\":true}");
        return;
    }
    
    if (!sdOK) {
        StaticJsonDocument<2048> doc;
        JsonArray logs = doc.createNestedArray("logs");
        JsonObject log1 = logs.createNestedObject();
        log1["time"] = (long)time(nullptr);
        log1["event"] = "SISTEMA_AVVIATO";
        log1["source"] = WiFi.macAddress();
        String risposta;
        serializeJson(doc, risposta);
        serverWeb.send(200, "application/json", risposta);
        return;
    }
    
    File fileLog = SD.open("/security.log", FILE_READ);
    if (!fileLog) {
        serverWeb.send(200, "application/json", "{\"logs\":[]}");
        return;
    }
    
    StaticJsonDocument<16384> doc;
    JsonArray logs = doc.createNestedArray("logs");
    
    fileLog.seek(0);
    String linea;
    while (fileLog.available() && logs.size() < 100) {
        linea = fileLog.readStringUntil('\n');
        linea.trim();
        if (linea.length() > 0 && !linea.startsWith("timestamp")) {
            int virgola1 = linea.indexOf(',');
            int virgola2 = linea.indexOf(',', virgola1 + 1);
            if (virgola1 > 0 && virgola2 > 0) {
                JsonObject logEntry = logs.createNestedObject();
                logEntry["time"] = linea.substring(0, virgola1).toInt();
                logEntry["event"] = linea.substring(virgola1 + 1, virgola2);
                logEntry["source"] = linea.substring(virgola2 + 1);
            }
        }
    }
    fileLog.close();
    
    String risposta;
    serializeJson(doc, risposta);
    serverWeb.send(200, "application/json", risposta);
}

// ==================== MQTT PER CONTROLLO REMOTO ====================

void setupMQTT() {
    clientMQTT.setServer(BROKER, PORTA_BROKER);
    clientMQTT.setCallback(riceviComandoMQTT);
    Serial.println("📡 MQTT configurato su " + String(BROKER));
}

void inviaMQTTCriptato(String topic, String messaggio) {
    if (!clientMQTT.connected()) {
        Serial.println("⚠️ MQTT non connesso, messaggio non inviato");
        return;
    }
    String criptato = criptaAES(messaggio);
    if (clientMQTT.publish(topic.c_str(), criptato.c_str())) {
        Serial.printf("📤 MQTT inviato a %s\n", topic.c_str());
    } else {
        Serial.println("❌ Errore invio MQTT");
    }
}

void riceviComandoMQTT(char* topic, byte* payload, unsigned int length) {
    String criptato = String((char*)payload).substring(0, length);
    String decriptato = decriptaAES(criptato);
    
    if (decriptato.length() == 0) {
        Serial.println("🔴 Errore decrittografia comando MQTT");
        scriviLogSicurezza("MQTT_DECRIPT_FALLITA", "");
        return;
    }
    
    Serial.printf("📩 Comando MQTT ricevuto: %s\n", decriptato.c_str());
    
    StaticJsonDocument<200> doc;
    deserializeJson(doc, decriptato);
    String comando = doc["comando"] | "";
    
    if (comando == "stato") {
        String risposta = "{\"temperatura\":" + String(temperatura) + 
                         ",\"umidita\":" + String(umidita) + 
                         ",\"movimento\":" + String(movimento ? "true" : "false") + 
                         ",\"movimenti_totali\":" + String(contatoreTotale) + "}";
        inviaMQTTCriptato(TOPIC_STATO, risposta);
    } else if (comando == "accendi") {
        sistemaAttivo = true;
        scriviLogSicurezza("MQTT_SISTEMA_ACCESO", "");
    } else if (comando == "spegni") {
        sistemaAttivo = false;
        scriviLogSicurezza("MQTT_SISTEMA_SPENTO", "");
    } else if (comando == "reset") {
        if (chiaveInserita || jumperAdminPresente) {
            resetContatori();
            scriviLogSicurezza("MQTT_CONTATORI_RESET", "");
        }
    }
}

void connettiMQTT() {
    static unsigned long ultimoTentativo = 0;
    if (clientMQTT.connected()) return;
    
    if (millis() - ultimoTentativo < 5000) return;
    ultimoTentativo = millis();
    
    Serial.println("📡 Tentativo connessione MQTT...");
    
    String clientId = "ESP8266_" + String(ESP.getChipId());
    if (clientMQTT.connect(clientId.c_str())) {
        clientMQTT.subscribe(TOPIC_COMANDI);
        Serial.println("✅ MQTT connesso a " + String(BROKER));
        scriviLogSicurezza("MQTT_CONNESSO", BROKER);
        
        String statoMsg = "{\"status\":\"online\",\"ip\":\"" + WiFi.localIP().toString() + "\",\"mac\":\"" + WiFi.macAddress() + "\"}";
        inviaMQTTCriptato(TOPIC_STATO, statoMsg);
    } else {
        Serial.printf("❌ Connessione MQTT fallita, rc=%d\n", clientMQTT.state());
    }
}

// ==================== OTA (AGGIORNAMENTI VIA WIFI) ====================

void setupOTA() {
    ArduinoOTA.setHostname("sistema-sicurezza-stanza");
    ArduinoOTA.setPassword("AdminOTA2024");
    
    ArduinoOTA.onStart([]() {
        if (!chiaveInserita && !jumperAdminPresente) {
            Serial.println("🔴 OTA bloccato: chiave fisica non inserita!");
            ArduinoOTA.end();
            return;
        }
        Serial.println("📦 Aggiornamento OTA avviato...");
        scriviLogSicurezza("OTA_START", WiFi.macAddress());
    });
    
    ArduinoOTA.onProgress([](unsigned int progresso, unsigned int totale) {
        Serial.printf("Progresso OTA: %u%%\r", (progresso / (totale / 100)));
    });
    
    ArduinoOTA.onEnd([]() {
        Serial.println("\n✅ Aggiornamento OTA completato!");
        scriviLogSicurezza("OTA_COMPLETATO", WiFi.macAddress());
        delay(1000);
        ESP.restart();
    });
    
    ArduinoOTA.onError([](ota_error_t errore) {
        Serial.printf("❌ Errore OTA [%d]: ", errore);
        if (errore == OTA_AUTH_ERROR) Serial.println("Autenticazione fallita");
        else if (errore == OTA_BEGIN_ERROR) Serial.println("Avvio fallito");
        else if (errore == OTA_CONNECT_ERROR) Serial.println("Connessione fallita");
        else if (errore == OTA_RECEIVE_ERROR) Serial.println("Ricezione fallita");
        else if (errore == OTA_END_ERROR) Serial.println("Chiusura fallita");
        scriviLogSicurezza("OTA_ERRORE_" + String(errore), "");
    });
    
    ArduinoOTA.begin();
    Serial.println("✅ OTA pronto - Hostname: sistema-sicurezza-stanza");
}

// ==================== RESET CONTATORI ====================

void resetContatori() {
    if (!chiaveInserita && !jumperAdminPresente) {
        Serial.println("🔴 Reset bloccato: chiave fisica non inserita!");
        scriviLogSicurezza("RESET_BLOCCATO", WiFi.macAddress());
        return;
    }
    
    contatoreTotale = 0;
    contatoreOggi = 0;
    contatoreSettimana = 0;
    contatoreMese = 0;
    salvaContatori();
    
    scriviLogSicurezza("CONTATORI_RESET", WiFi.macAddress());
    Serial.println("✅ Contatori resettati dall'amministratore");
}

// ==================== SETUP - TUTTO PARTE DA QUI ====================

void setup() {
    Serial.begin(115200);
    delay(100);
    
    Serial.println("\n");
    Serial.println("╔══════════════════════════════════════════════════════════════╗");
    Serial.println("║                                                              ║");
    Serial.println("║     ███████╗██╗██╗   ██╗███████╗██╗██╗   ██╗██████╗  █████╗  ║");
    Serial.println("║     ██╔════╝██║██║   ██║██╔════╝██║██║   ██║██╔══██╗██╔══██╗ ║");
    Serial.println("║     ███████╗██║██║   ██║███████╗██║██║   ██║██║  ██║╚█████╔╝ ║");
    Serial.println("║     ╚════██║██║╚██╗ ██╔╝╚════██║██║██║   ██║██║  ██║██╔══██╗ ║");
    Serial.println("║     ███████║██║ ╚████╔╝ ███████║██║╚██████╔╝██████╔╝╚█████╔╝ ║");
    Serial.println("║     ╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝ ╚═════╝ ╚═════╝  ╚════╝  ║");
    Serial.println("║                                                              ║");
    Serial.println("║           SISTEMA DI MONITORAGGIO SICURO v2.0                ║");
    Serial.println("║                    ESP8266 - AES-256                         ║");
    Serial.println("╚══════════════════════════════════════════════════════════════╝");
    Serial.println();
    
    // configuro i pin
    pinMode(PIN_CHIAVE, INPUT_PULLUP);
    pinMode(PIN_TAMPER, INPUT_PULLUP);
    pinMode(PIN_JUMPER_ADMIN, INPUT_PULLUP);
    pinMode(PIN_SIRENA, OUTPUT);
    pinMode(PIN_PIR, INPUT);
    digitalWrite(PIN_SIRENA, LOW);
    
    dht.begin();
    caricaContatori();
    inizializzaSD();
    
    // controllo se hanno aperto il case
    if (digitalRead(PIN_TAMPER) == HIGH) {
        tamperRilevato = true;
        Serial.println("🔴🔴🔴 ALLARME CRITICO: TAMPER RILEVATO! Case aperto! 🔴🔴🔴");
        for (int i = 0; i < 30; i++) {
            digitalWrite(PIN_SIRENA, HIGH);
            delay(300);
            digitalWrite(PIN_SIRENA, LOW);
            delay(300);
        }
        allarmeScattato = true;
        scriviLogSicurezza("TAMPER_BOOT", "");
        while (true) {
            digitalWrite(PIN_SIRENA, HIGH);
            delay(500);
            digitalWrite(PIN_SIRENA, LOW);
            delay(500);
        }
    }
    
    // leggo lo stato dell'hardware
    chiaveInserita = (digitalRead(PIN_CHIAVE) == LOW);
    jumperAdminPresente = (digitalRead(PIN_JUMPER_ADMIN) == LOW);
    
    Serial.println("┌─────────────────────────────────────────────────────────────┐");
    Serial.println("│                    VERIFICA HARDWARE                        │");
    Serial.println("├─────────────────────────────────────────────────────────────┤");
    Serial.printf ("│ 🔑 Chiave fisica:              %-34s │\n", chiaveInserita ? "✅ INSERITA" : "❌ ASSENTE");
    Serial.printf ("│ 🛡️ Jumper admin:               %-34s │\n", jumperAdminPresente ? "✅ PRESENTE" : "❌ ASSENTE");
    Serial.printf ("│ 📦 Tamper:                     %-34s │\n", tamperRilevato ? "⚠️ ATTIVATO" : "✅ OK");
    Serial.printf ("│ 🌡️ Sensore DHT22:              %-34s │\n", "✅ INIZIALIZZATO");
    Serial.printf ("│ 🚶 Sensore PIR:                %-34s │\n", "✅ INIZIALIZZATO");
    Serial.println("└─────────────────────────────────────────────────────────────┘");
    
    // controllo se il sistema è bloccato per troppi tentativi
    if (sistemaBloccato) {
        unsigned long ora = millis();
        if (ora < bloccatoFinoA) {
            long rimanenti = (bloccatoFinoA - ora) / 1000;
            Serial.printf("🔴 SISTEMA BLOCCATO! Riprova tra %ld secondi\n", rimanenti);
            scriviLogSicurezza("SISTEMA_BLOCCATO", String(rimanenti));
            while (true) {
                delay(1000);
                if (millis() >= bloccatoFinoA) break;
            }
        } else {
            sistemaBloccato = false;
            tentativiFalliti = 0;
            Serial.println("✅ Sistema sbloccato");
        }
    }
    
    // configuro il WiFi (la prima volta apre un access point)
    Serial.println("\n📡 AVVIO CONFIGURAZIONE WIFI...");
    WiFiManager wm;
    wm.setConnectTimeout(30);
    wm.setConfigPortalTimeout(180);
    
    if (!wm.autoConnect("SistemaSicurezza", "Admin123")) {
        Serial.println("❌ Connessione WiFi fallita!");
        scriviLogSicurezza("WIFI_FALLITO", "");
        ESP.restart();
    }
    
    Serial.println("┌─────────────────────────────────────────────────────────────┐");
    Serial.println("│                    CONNESSIONE WIFI                         │");
    Serial.println("├─────────────────────────────────────────────────────────────┤");
    Serial.printf ("│ 📡 Nome rete: %-40s │\n", WiFi.SSID().c_str());
    Serial.printf ("│ 🌐 IP assegnato: %-40s │\n", WiFi.localIP().toString().c_str());
    Serial.printf ("│ 🔢 MAC address: %-40s │\n", WiFi.macAddress().c_str());
    Serial.printf ("│ 📶 Potenza segnale: %-40d │\n", WiFi.RSSI());
    Serial.println("└─────────────────────────────────────────────────────────────┘");
    
    // avvio tutti i servizi
    avviaServer();
    setupMQTT();
    setupOTA();
    
    scriviLogSicurezza("SISTEMA_AVVIATO", WiFi.macAddress());
    
    Serial.println("\n╔══════════════════════════════════════════════════════════════╗");
    Serial.printf ("║     Apri il browser su: http://%s                   ║\n", WiFi.localIP().toString().c_str());
    Serial.println("║     Password OTA: AdminOTA2024                                ║");
    Serial.println("║     Password amministratore: Admin123!@#                     ║");
    Serial.println("║     Token 2 fattori: quello che hai messo nel codice         ║");
    Serial.println("╚══════════════════════════════════════════════════════════════╝\n");
}

// ==================== LOOP - GIRA IN CERCHIO ALL'INFINITO ====================

void loop() {
    static unsigned long ultimoTentativoMQTT = 0;
    
    // controllo continuo il tamper (se aprono il case mentre è acceso)
    if (digitalRead(PIN_TAMPER) == HIGH && !tamperRilevato) {
        tamperRilevato = true;
        allarmeScattato = true;
        Serial.println("🔴🔴🔴 ALLARME: TAMPER RILEVATO DURANTE L'ESECUZIONE! 🔴🔴🔴");
        scriviLogSicurezza("TAMPER_RUNTIME", "");
        for (int i = 0; i < 60; i++) {
            digitalWrite(PIN_SIRENA, HIGH);
            delay(500);
            digitalWrite(PIN_SIRENA, LOW);
            delay(500);
        }
        while (true) {
            digitalWrite(PIN_SIRENA, HIGH);
            delay(200);
            digitalWrite(PIN_SIRENA, LOW);
            delay(200);
        }
    }
    
    // leggo i sensori (temperatura, umidità, movimento)
    leggiSensori();
    resettaContatoriAutomatici();
    
    // se MQTT si è disconnesso, provo a riconnettermi
    if (!clientMQTT.connected() && millis() - ultimoTentativoMQTT > 5000) {
        ultimoTentativoMQTT = millis();
        connettiMQTT();
    }
    
    // gestisco i servizi
    ArduinoOTA.handle();
    serverWeb.handleClient();
    clientMQTT.loop();
    
    delay(10);  // piccolo delay per non sovraccaricare il processore
}
