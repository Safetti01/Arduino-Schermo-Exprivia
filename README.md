# 🔒 Sistema di Monitoraggio Sicuro per Ambienti – GUIDA COMPLETA

Uno schermo intelligente fai-da-te che si controlla dal telefono. 
Costa ~80€, registra tutto su SD card, ha la chiave fisica e la crittografia AES-256.  
Nessun cloud proprietario, nessun abbonamento. Funziona anche senza internet (solo in locale).

---

## 📦 1. COSA COMPRARE (LISTA DELLA SPESA)

| Componente               | Modello / Specifiche                | Prezzo (€) |
|--------------------------|--------------------------------------|-------------|
| Microcontrollore         | ESP8266 NodeMCU V3 (o Wemos D1 Mini) | 10          |
| Sensore temp/umidità     | DHT22 (meglio) o DHT11 (economico)   | 8 (o 3)     |
| Sensore movimento        | HC-SR501 (PIR)                       | 4           |
| Modulo SD Card           | Lettore SD 3.3V (solo 3.3V!)         | 3           |
| Schedina SD              | 4GB (formattata FAT32)               | 5           |
| Interruttore a chiave    | 2 posizioni, con chiave              | 7           |
| Microswitch tamper       | Finecorsa a levetta (3 pin)          | 2           |
| Jumper femmina           | 2.54mm passo                         | 1           |
| Buzzer (sirena)          | 5V, 85‑95dB                          | 3           |
| Alimentatore USB         | 5V / 2A (caricabatterie)             | 8           |
| Cavo MicroUSB            | 1 metro                              | 3           |
| Cavi jumper              | Femmina‑Femmina (pacco da 40)        | 3           |
| Breadboard               | 400 punti                            | 3           |

**Totale indicativo: 60‑80 €** (a seconda delle scelte).

---

## 🔌 2. COME COLLEGARE TUTTO (PIN PER PIN)

👉 **Regola d’oro**  
- 🔴 **ROSSO** → Alimentazione (3.3V o 5V)  
- ⚫ **NERO** → Terra (GND)  
- 🟡 **GIALLO** → Segnale dati (GPIO)

### Tabella dei collegamenti

| Componente     | Pin componente | Colore | Pin ESP8266        |
|----------------|----------------|--------|--------------------|
| **DHT22**      | VCC            | ROSSO  | 3V3                |
|                | DATA           | GIALLO | D4 (GPIO2)         |
|                | GND            | NERO   | GND                |
| **PIR**        | VCC            | ROSSO  | VIN (5V)           |
|                | OUT            | GIALLO | D3 (GPIO0)         |
|                | GND            | NERO   | GND                |
| **SD Card**    | VCC            | ROSSO  | 3V3                |
|                | GND            | NERO   | GND                |
|                | MISO           | GIALLO | D6 (GPIO12)        |
|                | MOSI           | GIALLO | D7 (GPIO13)        |
|                | SCK            | GIALLO | D5 (GPIO14)        |
|                | CS             | GIALLO | D8 (GPIO15)        |
| **Chiave**     | COMUNE         | NERO   | GND                |
|                | NO             | GIALLO | D1 (GPIO5)         |
| **Tamper**     | COMUNE         | NERO   | GND                |
|                | NO             | GIALLO | D2 (GPIO4)         |
| **Jumper**     | PIN1           | NERO   | GND                |
|                | PIN2           | GIALLO | D0 (GPIO16)        |
| **Buzzer**     | POSITIVO (+)   | GIALLO | D3 (GPIO0)         |
|                | NEGATIVO (-)   | NERO   | GND                |

> ⚠️ **Attenzione**:  
> - Il PIR va alimentato a **5V** (collegarlo a `VIN`).  
> - Il modulo SD Card deve essere **3.3V** (quelli a 5V bruciano l’ESP).  
> - Per il DHT22, se i valori sono instabili, aggiungi una resistenza da 10kΩ tra DATA e 3V3.

---

## 💻 3. INSTALLAZIONE SOFTWARE (Arduino IDE)

### 3.1 Installa Arduino IDE  
Scarica da [arduino.cc](https://www.arduino.cc/en/software)

### 3.2 Aggiungi il supporto per ESP8266  
1. **File → Preferenze**  
2. Nel campo *URL aggiuntivi gestori schede* incolla:  
   `https://arduino.esp8266.com/stable/package_esp8266com_index.json`  
3. OK

### 3.3 Installa la scheda ESP8266  
- **Strumenti → Scheda → Gestore Schede**  
- Cerca `esp8266` → installa **esp8266 by ESP8266 Community** (versione 3.1.2)

### 3.4 Installa le librerie necessarie  
**Sketch → Include Library → Manage Libraries** → cerca e installa:

| Libreria           | Versione  |
|--------------------|-----------|
| WiFiManager        | 2.0.17    |
| PubSubClient       | 2.8       |
| DHT sensor library | 1.4.4     |
| ArduinoJson        | 6.21.0    |
| AESLib             | 1.0.0     |

*(ArduinoOTA, EEPROM, SPI, SD, time sono già incluse)*

### 3.5 Seleziona la scheda e la porta  
- **Strumenti → Scheda → ESP8266 Boards → NodeMCU 1.0 (ESP‑12E Module)**  
- **Strumenti → Porta** → scegli la porta del tuo ESP8266

---

## 📥 4. CARICARE IL CODICE SULL’ESP8266

1. Copia l’intero sketch `sketch_apr26a.ino` (le ~1600 righe) nell’IDE.  
2. (Opzionale) Modifica questi valori prima del caricamento:

```cpp
// Token per il secondo fattore (cambialo con uno tuo)
const char* ADMIN_API_TOKEN = "m9xK#pL2$vN8*qR5&wE7!tY3@uI1^oJ6";

// Whitelist MAC: solo questi dispositivi possono parlare con il sistema
const char* MAC_WHITELIST[] = {
    "AA:BB:CC:DD:EE:FF",   // ← metti il MAC del tuo telefono
    "11:22:33:44:55:66"    // ← metti il MAC del tuo PC
};
