# 🔒 Sistema di Monitoraggio Sicuro per Ambienti

> Un sistema di sorveglianza intelligente fai-da-te che si controlla dal telefono.  
> Costa **~80€**, registra tutto su SD card, ha la **chiave fisica** e la **crittografia AES-256**.  
> **Nessun cloud proprietario, nessun abbonamento.** Funziona anche senza internet (solo in locale).

---

## 📖 INDICE

1. [Cosa fa il sistema](#-cosa-fa-il-sistema)
2. [Cosa vede chi lo usa](#-cosa-vede-chi-lo-usa)
3. [Lista della spesa](#-1-cosa-comprare-lista-della-spesa)
4. [Collegamenti hardware](#-2-come-collegare-tutto-pin-per-pin)
5. [Installazione software](#-3-installazione-software-arduino-ide)
6. [Caricare il codice](#-4-caricare-il-codice-sullesp8266)
7. [Primo avvio](#-5-primo-avvio-e-configurazione-wifi)
8. [Comandi MQTT](#-6-comandi-mqtt-controllo-da-remoto)
9. [Problemi comuni](#-7-problemi-comuni-e-soluzioni)
10. [Sicurezza implementata](#-8-sicurezza-implementata)

---

## 🎯 COSA FA IL SISTEMA

| Funzione | Descrizione |
|----------|-------------|
| 🚶 **Conta le persone** | Sensore PIR rileva i movimenti e tiene il conto |
| 🌡️ **Temperatura e umidità** | Sensore DHT22 mostra i valori in tempo reale |
| 📱 **Pannello web** | Accesso da telefono, tablet o PC |
| 💾 **Log su SD card** | Ogni evento viene salvato con data e ora |
| 🔑 **Chiave fisica** | Solo chi ha la chiave può fare modifiche |
| 🚨 **Anti-tamper** | Se apri il case, scatta la sirena e si blocca |
| 🔒 **Crittografia AES-256** | Tutte le comunicazioni sono criptate |
| 🌍 **Comandi remoti MQTT** | Controllo da qualsiasi parte del mondo |
| 📡 **Aggiornamenti OTA** | Carichi nuovo firmware via WiFi |
| 🛡️ **Anti brute-force** | 5 tentativi sbagliati = blocco 5 minuti |

---

## 👥 COSA VEDE CHI LO USA

### 👤 UTENTE NORMALE (senza chiave)

**Vede (solo informazioni pubbliche):**

| Cosa vede | ✅ |
|-----------|----|
| 🌡️ Temperatura attuale | ✅ |
| 💧 Umidità attuale | ✅ |
| 🚪 Se la stanza è LIBERA o OCCUPATA | ✅ |
| 👤 Chi ha occupato la stanza | ✅ |
| 📅 Da quanto è occupata | ✅ |

**Non può fare:**
- ❌ Accedere al pannello admin
- ❌ Vedere i contatori movimenti
- ❌ Modificare nulla

> 👁️ L'utente normale **sa cosa succede nella stanza**, ma **non può cambiare nulla**.

---

### 🔐 ADMIN (con chiave fisica inserita)

**Vede (tutto):**

| Cosa vede | ✅ |
|-----------|----|
| Tutto ciò che vede l'utente normale | ✅ |
| 📊 Contatori movimenti (totali/oggi/settimana/mese) | ✅ |
| 📱 Whitelist MAC (dispositivi autorizzati) | ✅ |
| 📜 Log di sicurezza completi | ✅ |
| 🛡️ Stato hardware (chiave, jumper, tamper) | ✅ |
| ⏱️ Uptime del sistema | ✅ |

**Può fare:**

| Azione | ✅ |
|--------|----|
| 🔄 Resettare i contatori | ✅ |
| ➕ Aggiungere/rimuovere MAC dalla whitelist | ✅ |
| 🗑️ Cancellare i log di sicurezza | ✅ |
| ⚙️ Riavviare il sistema | ✅ |
| 📡 Aggiornare il firmware (OTA) | ✅ |

---

### 📋 RIASSUNTO VISIVO

| Cosa | 👤 Utente normale | 🔐 Admin |
|------|:-----------------:|:--------:|
| Temperatura e umidità | ✅ | ✅ |
| Stanza libera/occupata | ✅ | ✅ |
| Chi ha occupato | ✅ | ✅ |
| Contatori movimenti | ❌ | ✅ |
| Whitelist MAC | ❌ | ✅ |
| Log di sicurezza | ❌ | ✅ |
| Resettare contatori | ❌ | ✅ |
| Modificare whitelist | ❌ | ✅ |
| Cancellare log | ❌ | ✅ |
| Riavviare sistema | ❌ | ✅ |

---

## 📦 1. COSA COMPRARE (LISTA DELLA SPESA)

| Componente | Modello | Prezzo (€) |
|------------|---------|-------------|
| Microcontrollore | ESP8266 NodeMCU V3 | 10 € |
| Sensore temp/umidità | DHT22 (o DHT11) | 8 € (o 3 €) |
| Sensore movimento | HC-SR501 (PIR) | 4 € |
| Modulo SD Card | Lettore SD 3.3V | 3 € |
| Schedina SD | 4GB (FAT32) | 5 € |
| Interruttore a chiave | 2 posizioni | 7 € |
| Microswitch tamper | Finecorsa | 2 € |
| Jumper femmina | 2.54mm | 1 € |
| Buzzer (sirena) | 5V (85‑95dB) | 3 € |
| Alimentatore USB | 5V / 2A | 8 € |
| Cavo MicroUSB | 1 metro | 3 € |
| Cavi jumper | Femmina-Femmina (40 pz) | 3 € |
| Breadboard | 400 punti | 3 € |

**Totale indicativo: 60‑80 €**

---

## 🔌 2. COME COLLEGARE TUTTO (PIN PER PIN)

### Regola d'oro dei colori

| Colore | Significato |
|--------|-------------|
| 🔴 **ROSSO** | Alimentazione (3.3V o 5V) |
| ⚫ **NERO** | Terra (GND) |
| 🟡 **GIALLO** | Segnale dati (GPIO) |

### Tabella dei collegamenti

| Componente | Pin | Colore | Pin ESP8266 |
|------------|-----|--------|-------------|
| **DHT22** | VCC | 🔴 ROSSO | 3V3 |
| | DATA | 🟡 GIALLO | D4 (GPIO2) |
| | GND | ⚫ NERO | GND |
| **PIR** | VCC | 🔴 ROSSO | VIN (5V) |
| | OUT | 🟡 GIALLO | D3 (GPIO0) |
| | GND | ⚫ NERO | GND |
| **SD Card** | VCC | 🔴 ROSSO | 3V3 |
| | GND | ⚫ NERO | GND |
| | MISO | 🟡 GIALLO | D6 (GPIO12) |
| | MOSI | 🟡 GIALLO | D7 (GPIO13) |
| | SCK | 🟡 GIALLO | D5 (GPIO14) |
| | CS | 🟡 GIALLO | D8 (GPIO15) |
| **Chiave** | COMUNE | ⚫ NERO | GND |
| | NO | 🟡 GIALLO | D1 (GPIO5) |
| **Tamper** | COMUNE | ⚫ NERO | GND |
| | NO | 🟡 GIALLO | D2 (GPIO4) |
| **Jumper** | PIN1 | ⚫ NERO | GND |
| | PIN2 | 🟡 GIALLO | D0 (GPIO16) |
| **Buzzer** | (+) | 🟡 GIALLO | D3 (GPIO0) |
| | (-) | ⚫ NERO | GND |

> ⚠️ **Attenzioni importanti:**
> - Il **PIR** va alimentato a **5V** (collegarlo a `VIN`, NON a 3V3)
> - Il modulo **SD Card** deve essere **3.3V** (quelli a 5V bruciano l'ESP)
> - Per il DHT22, se i valori sono instabili, aggiungi una **resistenza da 10kΩ** tra DATA e 3V3

---

## 💻 3. INSTALLAZIONE SOFTWARE (Arduino IDE)

### Passo 1: Installa Arduino IDE
Scarica da [arduino.cc](https://www.arduino.cc/en/software)

### Passo 2: Aggiungi il supporto per ESP8266
1. **File → Preferenze**
2. Nel campo *URL aggiuntivi gestori schede* incolla:  
   `https://arduino.esp8266.com/stable/package_esp8266com_index.json`
3. Clicca OK

### Passo 3: Installa la scheda ESP8266
- **Strumenti → Scheda → Gestore Schede**
- Cerca `esp8266`
- Installa **esp8266 by ESP8266 Community** (versione 3.1.2)

### Passo 4: Installa le librerie
**Sketch → Include Library → Manage Libraries** → cerca e installa:

| Libreria | Versione |
|----------|----------|
| WiFiManager | 2.0.17 |
| PubSubClient | 2.8 |
| DHT sensor library | 1.4.4 |
| ArduinoJson | 6.21.0 |
| AESLib | 1.0.0 |

> 📌 **Nota:** ArduinoOTA, EEPROM, SPI, SD, time sono già incluse nell'IDE.

### Passo 5: Seleziona la scheda e la porta
- **Strumenti → Scheda → ESP8266 Boards → NodeMCU 1.0 (ESP-12E Module)**
- **Strumenti → Porta** → scegli la porta del tuo ESP8266

---

## 📥 4. CARICARE IL CODICE SULL'ESP8266

1. Copia l'intero codice `sketch_apr26a.ino` nell'Arduino IDE
2. (Opzionale) Modifica questi valori prima del caricamento:

```cpp
// Token per il secondo fattore (cambialo con uno tuo!)
const char* ADMIN_API_TOKEN = "m9xK#pL2$vN8*qR5&wE7!tY3@uI1^oJ6";

// Whitelist MAC: solo questi dispositivi possono parlare con il sistema
const char* MAC_WHITELIST[] = {
    "AA:BB:CC:DD:EE:FF",   // ← Il MAC del tuo telefono
    "11:22:33:44:55:66"    // ← Il MAC del tuo computer
};
