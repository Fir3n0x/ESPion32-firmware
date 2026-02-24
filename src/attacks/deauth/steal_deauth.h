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

#define MAX_CAPTURED_FRAMES  64
#define MAX_FRAME_SIZE       512


// Client                    AP
//   |                        |
//   |<── Deauth (toi) ──────|   <- We want that
//   |                        |
//   |──── Probe Request ────>|
//   |<── Probe Response ────|
//   |──── Auth Request ─────>|
//   |<── Auth Response ─────|
//   |──── Assoc Request ────>|
//   |<── Assoc Response ────|
//   |                        |
//   |<── EAPOL MSG 1 ───────|   <- Begin 4-way handshake
//   |──── EAPOL MSG 2 ──────>|   <- contain MIC -> we look for that
//   |<── EAPOL MSG 3 ───────|
//   |──── EAPOL MSG 4 ──────>|


typedef enum {
    STEAL_IDLE,
    STEAL_DEAUTHING,
    STEAL_LISTENING,
    STEAL_HANDSHAKE_CAPTURED,
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

void start_deauth_steal_attack(char *target, char *ap, int channel);
void stop_deauth_steal_attack(void);
void steal_export_pcap_ble(void); // send .pcap via ble

#endif