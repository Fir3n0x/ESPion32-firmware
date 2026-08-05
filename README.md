# ESPion32-firmware

Firmware ESP-IDF (C) pour ESP32 (`esp32doit-devkit-v1`) — outil d'audit WiFi
red team : injection 802.11 (deauth), capture de handshakes EAPOL / PMKID, et
beacon spam. Piloté en BLE par l'app Android **ESPion32**.

> Usage strictement autorisé (pentest / audit sur des réseaux dont on a la
> permission). L'injection 802.11 et le deauth sont réglementés.

## Build & flash

```bash
pio run                 # compile
pio run -t upload       # flash
pio device monitor      # log série @115200
```

- Framework : `espidf` (PlatformIO), partition `huge_app.csv` (app 3 MB).
- L'injection repose sur le contournement du sanity-check dans
  `src/wifi/wsl_bypasser/` (lié via `-Wl,-zmuldefs`).

## Architecture (src/)

| Module | Rôle |
|--------|------|
| `main.c` | init NVS/WiFi/BLE, tâches, `WIFI_PS_NONE` |
| `ble/BleManager` | serveur GATT (bluedroid), notifications, `bleSenderTask` (draine `macQueue`) |
| `command/command` | parseur du protocole texte |
| `common/SharedState` | globals (`deauthActive`, `captureActive`, `macQueue`, …) |
| `wifi/WifiManager` | init WiFi, filtre promiscuous, `onBleDisconnect` |
| `attacks/deauth` | `classic_deauth` (deauth continu), `steal_deauth` (capture), `test_deauth` (test d'efficacité + PMF) |
| `attacks/sniffer` | énumération des clients d'un AP |
| `attacks/bfs` | beacon frame spam |

## Protocole BLE (référence)

C'est le **contrat** entre le firmware et l'app. Toute évolution doit rester
synchronisée des deux côtés (voir `model/Command.kt` et `ble/BleMessageParser.kt`
côté app).

- **Device name** : `GoPro 8690`
- **Service** : `4fafc201-1fb5-459e-8fcc-c5c9c331914b`
- **CMD** (app → ESP32, WRITE) : `beb5483e-36e1-4688-b7f5-ea07361b26a8`
- **STATUS** (ESP32 → app, NOTIFY, CCCD `2902`) : `9d8c2d3a-7a12-4d3f-8f58-bc6b4f9c1123`
- **MTU** : 384

### Commandes (app → ESP32)

Format `TYPE|ACTION|KEY=VALUE|...` (ASCII, séparateur `|`).

| Commande | Effet |
|----------|-------|
| `SNIFF\|START\|SSID=..\|BSSID=..\|CHANNEL=..` | énumère les clients de l'AP |
| `SNIFF\|STOP` | arrête le sniffer |
| `DEAUTH\|START\|TARGET=<mac>\|AP=<mac>\|CHANNEL=<n>\|ATTACKMODE=<1-4>` | voir modes ci-dessous |
| `DEAUTH\|TEST\|TARGET=..\|AP=..\|CHANNEL=..` | test d'efficacité (baseline + PMF + post-attaque) |
| `DEAUTH\|STOP` | arrêt coopératif (tous modes) |
| `BEACON\|START\|CHANNEL=..\|SSIDS=a~b~c` | beacon spam (SSID séparés par `~`) |
| `BEACON\|STOP` | arrête le beacon spam |
| `MAC\|CLEAR` / `WIFI\|CLEAR` | reset des variables |
| `EVILTWIN\|...` | **non implémenté** (stub) |

**`ATTACKMODE`** (commande `DEAUTH|START`) :

| Id | Mode | Description |
|----|------|-------------|
| 1 | Deauth classique | déconnexion continue, sans capture |
| 2 | Handshake par deauth | deauth du client + capture de la reconnexion |
| 3 | Capture passive | écoute seule, attend qu'un client s'associe (furtif) |
| 4 | PMKID | capture du PMKID depuis M1 (repli sur handshake si indispo) |

### Événements (ESP32 → app)

| Événement | Sens |
|-----------|------|
| `LOG\|<SNIFF\|DEAUTH\|STEAL\|BEACON>\|msg=..` | log applicatif |
| `MAC\|SNIFF\|mac=..\|rssi=..\|ch=..` | client découvert |
| `STATUS\|<MODULE>\|value=..` | ex. `STATUS\|DEAUTH\|value=STARTED\|STOPPED` (acquittement) |
| `ERROR\|<MODULE>\|msg=..` | erreur |
| `PCAP\|START\|size=<octets>\|frames=<n>` | début d'export capture |
| `PCAP\|CHUNK\|<index>\|<base64>` | fragment (positionnel, ~180 o/chunk) |
| `PCAP\|END\|crc=0x........` | fin + CRC32 (32 bits non signés) |

## Chaîne de capture (steal_deauth)

- La capture **reste en mode promiscuous en permanence** et injecte via
  `WIFI_IF_AP` sans jamais couper le sniffer (le mode AP permet TX + RX
  promiscuous simultanés).
- Le callback RX est **non bloquant** : il ne fait que filtrer, stocker
  (`captured_frames`) et poser des drapeaux. Les notifications BLE partent de la
  boucle de la tâche.
- Stocke beacon + assoc/reassoc + toutes les EAPOL (M1–M4, bitmask). Succès dès
  qu'une paire exploitable est présente (M1+M2, M2+M3 ou M3+M4), avec fenêtre de
  grâce pour M3/M4. Le PCAP est ensuite streamé sur BLE.

### Exploitation (poste d'analyse)

```bash
hcxpcapngtool -o hash.22000 capture.pcap
hashcat -m 22000 hash.22000 wordlist.txt
```

## Notes de fiabilité

- Coexistence BLE/WiFi en `PREFER_BALANCE` pendant les attaques (pas `PREFER_BT`).
- `WIFI_PS_NONE` dès le boot ; `FREERTOS_HZ=1000`.
- Arrêt d'attaque **coopératif** (jamais de `vTaskDelete` en plein `esp_wifi_80211_tx`).
- Alim USB stable recommandée (les rafales d'injection sollicitent la radio).

Voir `Changelog.md` pour le détail des évolutions.
