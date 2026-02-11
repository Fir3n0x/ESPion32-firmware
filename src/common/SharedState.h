#ifndef SHARED_STATE_H
#define SHARED_STATE_H

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <stdbool.h>
#include <stdint.h>


// ========== MAC STRUCTURE ==========
typedef struct {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
} mac_event_t;

// ========== 802.11 STRUCTURES ==========
typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6];  // Destination
  uint8_t addr2[6];  // Source
  uint8_t addr3[6];  // BSSID
  uint16_t seq_ctrl;
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[];
} wifi_ieee80211_packet_t;

// Global variables
extern volatile bool snifferActive;
extern volatile bool deauthActive;
extern volatile bool bfsActive;
extern volatile uint32_t totalPackets;
extern volatile uint32_t filteredPackets;
extern volatile QueueHandle_t macQueue;
extern volatile bool isAttackActive;
extern volatile char targetSSID[96]; // Set your target SSID
extern volatile char targetBSSID[18]; // Specific BSSID
extern volatile uint8_t targetChannel; // WiFi channel (1-13)

#endif