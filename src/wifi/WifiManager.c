#include "WifiManager.h"
#include "common/SharedState.h"
#include <string.h>
#include <stdio.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ========== WIFI SETTINGS ==========
static const char* TAG = "WifiManager";

// ========== CONFIGURATION ==========
static const char* targetSSID = "Livebox";  // Set your target SSID
static const char* targetBSSID = "MAC";                 // Optional: specific BSSID (lowercase)
uint8_t targetChannel = 6;               // WiFi channel (1-13)
bool filterBySSID = true;                // Enable SSID filtering
bool showBeacons = true;                 // Show beacon frames
bool showData = true;                    // Show data frames
bool showControl = false;                // Show control frames

// ========== PACKET STATISTICS ==========
unsigned long lastStatsTime = 0;

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

// ========== HELPER FUNCTIONS ==========
void macToString(const uint8_t* mac, char* buf) {
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* getFrameType(uint8_t type, uint8_t subtype) {
  if (type == 0) {  // Management
    switch (subtype) {
      case 0: return "AssocReq";
      case 1: return "AssocResp";
      case 4: return "ProbeReq";
      case 5: return "ProbeResp";
      case 8: return "Beacon";
      case 10: return "Disassoc";
      case 11: return "Auth";
      case 12: return "Deauth";
      default: return "Mgmt";
    }
  } else if (type == 1) {  // Control
    return "Control";
  } else if (type == 2) {  // Data
    return "Data";
  }
  return "Unknown";
}

// Extract SSID from beacon/probe response
int extractSSID(const uint8_t* payload, uint16_t len, char* ssid_out) {
  if (len < 38) return 0;
  
  // SSID is in the first tagged parameter after fixed fields
  uint8_t ssidLen = payload[37];
  if (ssidLen == 0 || ssidLen > 32 || (37 + 1 + ssidLen) > len) {
    return 0;
  }
  
  memcpy(ssid_out, &payload[38], ssidLen);
  ssid_out[ssidLen] = '\0';
  return ssidLen;
}

// Compare MAC addresses (case-insensitive)
bool macMatches(const uint8_t* mac, const char* target) {
    if (target == NULL || target[0] == '\0') return true;
    
    char macStr[18];
    macToString(mac, macStr);
    
    // Simple case-insensitive compare
    for (int i = 0; i < 17; i++) {
        char a = macStr[i];
        char b = target[i];
        if (a >= 'A' && a <= 'Z') a += 32;  // to lowercase
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return false;
    }
    return true;
}

// ========== SNIFFER CALLBACK ==========
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if(!snifferActive) return;
  totalPackets = filteredPackets + 1;
  
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  mac_event_t evt;
  memcpy(evt.mac, hdr->addr2, 6);
  evt.rssi = pkt->rx_ctrl.rssi;
  evt.channel = pkt->rx_ctrl.channel;

  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  xQueueSendFromISR(macQueue, &evt, &xHigherPriorityTaskWoken);

  
  uint16_t frameCtrl = hdr->frame_ctrl;
  uint8_t frameType = (frameCtrl & 0x0C) >> 2;
  uint8_t frameSubtype = (frameCtrl & 0xF0) >> 4;
  
  // Apply frame type filters
  if (frameType == 0 && !showBeacons && (frameSubtype == 8 || frameSubtype == 5)) return;
  if (frameType == 2 && !showData) return;
  if (frameType == 1 && !showControl) return;
  
  // Optional BSSID filter
  if (strlen(targetBSSID) > 0 && !macMatches(hdr->addr3, targetBSSID)) {
    return;
  }
  
  // SSID filtering for beacons and probe responses
  if (filterBySSID && (frameSubtype == 8 || frameSubtype == 5)) {
    char ssid[33] = {0};
    int ssidLen = extractSSID(pkt->payload, pkt->rx_ctrl.sig_len, ssid);
    if (ssidLen == 0 || strcmp(ssid, targetSSID) != 0) {
      return;
    }
  }
  
  filteredPackets = filteredPackets + 1;
  
  // Log packet info
  char src[18], dst[18], bssid[18];
  macToString(hdr->addr2, src);
  macToString(hdr->addr1, dst);
  macToString(hdr->addr3, bssid);
  
  ESP_LOGI(TAG, "[%7lu] RSSI:%3d CH:%2d %10s SRC:%s DST:%s BSSID:%s",
          filteredPackets, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel,
          getFrameType(frameType, frameSubtype), src, dst, bssid);
  
  // Show SSID for beacons/probe responses
  if (frameSubtype == 8 || frameSubtype == 5) {
      char ssid[33] = {0};
      if (extractSSID(pkt->payload, pkt->rx_ctrl.sig_len, ssid) > 0) {
          ESP_LOGI(TAG, "  SSID: %s", ssid);
      }
  }
}


void startWiFiSniffer() {
  if(snifferActive) return;

    // Enable promiscuous mode
  esp_wifi_set_promiscuous(true);
  snifferActive = true;
  
  ESP_LOGI(TAG, "WiFi Sniffer STARTED");
  lastStatsTime = esp_timer_get_time() / 1000;
}

void stopWiFiSniffer() {
  if (!snifferActive) return;

  esp_wifi_set_promiscuous(false);
  snifferActive = false;

  ESP_LOGI(TAG, "WiFi Sniffer STOPPED");
}

void printWiFiStats() {
    if (!snifferActive) return;
    
    unsigned long now = esp_timer_get_time() / 1000;
    if (now - lastStatsTime > 10000) {
        ESP_LOGI(TAG, "\n[STATS] Total: %lu | Filtered: %lu | Rate: %.1f pkt/s\n",
                 totalPackets, filteredPackets, filteredPackets / 10.0);
        filteredPackets = 0;
        totalPackets = 0;
        lastStatsTime = now;
    }
}

// WIFI intialization
void WifiManager_Init() {

    ESP_LOGI(TAG, "Initializing WiFi Sniffer...");
    ESP_LOGI(TAG, "Target SSID: %s", targetSSID);
    ESP_LOGI(TAG, "Target BSSID: %s", targetBSSID);
    ESP_LOGI(TAG, "Channel: %d", targetChannel);
    ESP_LOGI(TAG, "Filters: Beacons=%d Data=%d Control=%d",
             showBeacons, showData, showControl);

  // Initialize WiFi in station mode
  vTaskDelay(pdMS_TO_TICKS(100));

  // Set channel
  esp_err_t err = esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to set channel %d: %s", targetChannel, esp_err_to_name(err));
  } else {
    ESP_LOGI(TAG, "Channel set to %d", targetChannel);
  }
  
  // Configure promiscuous filter
  wifi_promiscuous_filter_t filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | 
                   WIFI_PROMIS_FILTER_MASK_DATA |
                   WIFI_PROMIS_FILTER_MASK_CTRL
  };
  esp_wifi_set_promiscuous_filter(&filter);
  
  // Set callback
  esp_wifi_set_promiscuous_rx_cb(snifferCallback);

  ESP_LOGI(TAG, "WiFi Sniffer initialized");
}