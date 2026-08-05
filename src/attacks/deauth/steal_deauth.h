#ifndef STEAL_DEAUTH_H
#define STEAL_DEAUTH_H

#include "common/SharedState.h"
#include "attacks/deauth/Deauth.h"
#include "ble/BleManager.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_CAPTURED_FRAMES  128
#define MAX_FRAME_SIZE       512
#define MAX_STORED_BEACONS   4     // limite de beacons stockés (évite de saturer le buffer)

// EAPOL message bitmask (bit i => message i vu)
#define EAPOL_M1  (1 << 1)
#define EAPOL_M2  (1 << 2)
#define EAPOL_M3  (1 << 3)
#define EAPOL_M4  (1 << 4)

// Client                    AP
//   |                        |
//   |<── Deauth (nous) ─────|   <- mode DEAUTH uniquement
//   |──── Assoc Request ────>|
//   |<── Assoc Response ────|
//   |<── EAPOL MSG 1 ───────|   <- ANonce (+ PMKID éventuel dans le KDE RSN)
//   |──── EAPOL MSG 2 ──────>|   <- SNonce + MIC
//   |<── EAPOL MSG 3 ───────|
//   |──── EAPOL MSG 4 ──────>|

// Mode de capture demandé par l'opérateur
typedef enum {
    CAPTURE_PASSIVE = 0,   // écoute seule, aucun deauth
    CAPTURE_DEAUTH  = 1,   // deauth + capture du handshake au reconnect
    CAPTURE_PMKID   = 2     // deauth léger + capture du PMKID depuis M1
} capture_mode_t;

typedef enum {
    STEAL_IDLE,
    STEAL_DEAUTHING,
    STEAL_LISTENING,
    STEAL_HANDSHAKE_CAPTURED,
    STEAL_PMKID_CAPTURED,
    STEAL_FAILED
} steal_state_t;

typedef struct {
    uint64_t timestamp_us;
    uint16_t len;
    uint8_t  data[MAX_FRAME_SIZE];
} pcap_frame_t;

// PCAP headers
typedef struct __attribute__((packed)) {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_global_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_record_header_t;

// mode = capture_mode_t
void start_deauth_steal_attack(char *target, char *ap, int channel, int mode);
void stop_deauth_steal_attack(void);
void steal_export_pcap_ble(void); // envoie le .pcap via BLE

#endif
