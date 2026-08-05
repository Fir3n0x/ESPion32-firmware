# Changelog

Toutes les modifications notables de ce firmware sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

## [Unreleased]

### Fixed
- **Capture de handshake fiabilisée** : le mode « steal » ne bascule plus entre
  promiscuous et AP à chaque salve de deauth. Le sniffer reste actif en
  permanence pendant l'injection, ce qui évite de rater les trames EAPOL du
  reconnect (cause racine des handshakes manqués). `steal_deauth.c`.
- **Callback RX non bloquant** : plus d'appels `ESP_LOGI`/`BleManager_SendStatus`
  dans le handler promiscuous. Les notifications BLE et les logs sont émis depuis
  la boucle de la tâche sur transition d'état, ce qui supprime les pertes de
  paquets dans le chemin RX WiFi. `steal_deauth.c`.
- **Canal par défaut invalide** : `targetChannel` initialisé à `1` au lieu de
  `-1` (qui devenait `255` en `uint8_t` et faisait échouer `esp_wifi_set_channel`
  au boot). `SharedState.c`.
- **Arrêt d'attaque coopératif** : `stop_deauth_attack()` attend la sortie propre
  de la tâche (drapeau `deauthActive`) au lieu de la tuer avec `vTaskDelete` en
  plein `esp_wifi_80211_tx` ; un `DEAUTH|STOP` fonctionne désormais pour tous les
  modes. `classic_deauth.c`, `command.c`.

### Changed
- **Coexistence BLE/WiFi** : `ESP_COEX_PREFER_BALANCE` pendant les attaques au
  lieu de `ESP_COEX_PREFER_BT`, pour rendre de l'airtime au WiFi (injection +
  capture) sans casser le lien BLE de contrôle. `Deauth.c`.
- **Power save désactivé au boot** (`esp_wifi_set_ps(WIFI_PS_NONE)`) pour
  stabiliser injection et capture. `main.c`.
- **Débit d'injection** : délais inter-trames en microsecondes
  (`esp_rom_delay_us`) au lieu de `vTaskDelay(5 ms)` arrondi à un tick de 10 ms.
  `FREERTOS_HZ` passé à 1000. `classic_deauth.c`, `steal_deauth.c`, sdkconfig.

### Added
- **Trois modes de capture sélectionnables** via `ATTACKMODE` de la commande
  `DEAUTH|START` :
  - `2` = handshake par deauth + reconnexion (existant, fiabilisé).
  - `3` = capture passive (attend qu'un client s'associe, sans deauth).
  - `4` = PMKID (extraction du PMKID depuis le message M1 / KDE RSN, exploitable
    hashcat mode 22000).
- **Capture du handshake complet** : reconnaissance et stockage de M1/M2/M3/M4
  (bitmask) + beacon et assoc/reassoc de la cible, au lieu de s'arrêter à M2.
- **Acquittements `STATUS`** : `STATUS|DEAUTH|value=STARTED|STOPPED` pour piloter
  l'état côté application.
- Log explicite quand le buffer de capture est plein.
- **Budget DRAM** : `captured_frames` dimensionné à `80 × 384 o` (< la taille
  d'origine `64 × 512 o`) pour éviter le dépassement de `.dram0.bss` au link,
  tout en gardant de quoi capturer un handshake complet.

### Phase 2 — Optimisation des autres attaques

#### Fixed
- **Sniffer : callback RX non bloquant** (`Sniffer.c`) — `logDevice` ne fait plus
  d'`ESP_LOGI`/`BleManager_SendStatus` synchrone dans le chemin RX WiFi ; seule
  la livraison du MAC via `macQueue`/`bleSenderTask` est conservée. Supprime les
  pertes de paquets et le flood BLE par paquet.
- **Beacon spam : arrêt coopératif** (`BFS.c`) — plus de `vTaskDelete` en plein
  `esp_wifi_80211_tx`.

#### Changed
- **Beacon spam : débit d'injection** (`BFS.c`) — remplacement du `vTaskDelay(100 ms)`
  entre chaque envoi (≈10 beacons/s) par une rafale à gap fin (`esp_rom_delay_us`)
  + un yield 1 tick par SSID (≈ plusieurs centaines de beacons/s). Coexistence
  `PREFER_BALANCE` au lieu de `PREFER_BT`. Intervalle beacon annoncé ramené à
  100 ms pour une meilleure visibilité des SSID.

### Phase 3 — Documentation & nettoyage

#### Added
- **README** complet : build/flash, architecture, et **spécification du
  protocole BLE faisant autorité** (UUIDs, commandes, événements, modes de
  capture, workflow hashcat).

#### Removed
- Suppression de blocs de code mort commentés dans `BFS.c` (ancien template
  `packet[]`, helpers `init_ssids`/`change_ssid` jamais utilisés).
