#include "WifiManager.h"
#include "common/SharedState.h"
#include "ble/BleManager.h"
#include "wifi/DeauthAttack.h"
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
static char targetSSID[96] = {0};  // Set your target SSID
static char targetBSSID[18] = {0};                 // Optional: specific BSSID (lowercase)
uint8_t targetChannel = -1;               // WiFi channel (1-13)

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
    
    // Compare majuscule
    return strcmp(macStr, target) == 0;
}

void logDevice(wifi_promiscuous_pkt_t *pkt, uint8_t *actualBSSID, uint8_t *clientMAC) {
  // Retrieve structure
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  uint16_t frameCtrl = hdr->frame_ctrl;
  uint8_t frameType = (frameCtrl & 0x0C) >> 2;
  uint8_t frameSubtype = (frameCtrl & 0xF0) >> 4;

  // Increment filteredPacket
  filteredPackets++;

  mac_event_t evt;
  memcpy(evt.mac, clientMAC, 6);  // Use passed client MAC
  evt.rssi = pkt->rx_ctrl.rssi;
  evt.channel = pkt->rx_ctrl.channel;
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  xQueueSendFromISR(macQueue, &evt, &xHigherPriorityTaskWoken);
  
  // Log packet info
  char src[18], dst[18], bssid[18];
  macToString(hdr->addr2, src);
  macToString(hdr->addr1, dst);
  macToString(actualBSSID, bssid); 

  char result[256];
  snprintf(result, sizeof(result), "LOG|SNIFF|msg=[%7lu] RSSI:%3d CH:%2d %10s SRC:%s DST:%s BSSID:%s",
          filteredPackets, pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel,
          getFrameType(frameType, frameSubtype), src, dst, bssid);
  
  ESP_LOGI(TAG, "%s", result);

  BleManager_SendStatus(result);
}

// ========== SNIFFER CALLBACK ==========
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if(!snifferActive) return;

  // Increment total packet seen
  totalPackets++;
  
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  uint16_t frameCtrl = hdr->frame_ctrl;
  uint8_t frameType = (frameCtrl & 0x0C) >> 2;
  uint8_t frameSubtype = (frameCtrl & 0xF0) >> 4;

  // ✅ DEBUG: Log tous les 100 paquets pour voir ce qu'on capture
  if (totalPackets % 100 == 0) {
      char addr1[18], addr2[18], addr3[18];
      macToString(hdr->addr1, addr1);
      macToString(hdr->addr2, addr2);
      macToString(hdr->addr3, addr3);
      ESP_LOGI(TAG, "PKT#%lu Type:%d Sub:%d | A1:%s A2:%s A3:%s | Target:%s", 
               totalPackets, frameType, frameSubtype, 
               addr1, addr2, addr3, targetBSSID);
  }

  // Management frame (type 0)
  if (frameType == 0) {
      // Association Request (0) or Reassociation Request (2)
      if (frameSubtype == 0 || frameSubtype == 2) {
          // addr3 is the BSSID, addr2 is the client MAC
          if (macMatches(hdr->addr3, targetBSSID)) {
              char clientMAC[18];
              macToString(hdr->addr2, clientMAC);
              ESP_LOGI(TAG, "Device joined network: %s", clientMAC);
              logDevice(pkt, hdr->addr3, hdr->addr2);
          }
      }
       // Association response (1) or Reassociation response (3)
      else if(frameSubtype == 1 || frameSubtype == 3) {
        if (macMatches(hdr->addr2, targetBSSID)) { // AP check == addre2
          logDevice(pkt, hdr->addr2, hdr->addr1);
        }
      } // Probe request (4)
      // else if(frameSubtype == 4) {
      //   if(macMatches(hdr->addr3, targetBSSID)) {
      //     logDevice(pkt, hdr->addr3, hdr->addr2);
      //   }
      // } // Probe response (5)
      // else if(frameSubtype == 5) {
      //   if(macMatches(hdr->addr2, targetBSSID)) {
      //     logDevice(pkt, hdr->addr2, hdr->addr1);
      //   }
      // }
      // Disassociation (10)
      else if (frameSubtype == 10) {
          if (macMatches(hdr->addr3, targetBSSID)) {
              ESP_LOGI(TAG, "Client leaving: addr1=%02x:%02x... addr2=%02x:%02x...", 
                       hdr->addr1[0], hdr->addr1[1], hdr->addr2[0], hdr->addr2[1]);
          }
      }
       // Authentication (11)
      else if(frameSubtype == 11) {
        if (macMatches(hdr->addr3, targetBSSID)) {
          logDevice(pkt, hdr->addr3, hdr->addr2);
        }
      }
      // Deauthentication (12)
      else if (frameSubtype == 12) {
          if (macMatches(hdr->addr3, targetBSSID)) {
              char mac1[18], mac2[18];
              macToString(hdr->addr1, mac1);
              macToString(hdr->addr2, mac2);
              ESP_LOGI(TAG, "Deauthentication - addr1:%s addr2:%s", mac1, mac2);
              // client connected can be either addr1 or addr2
              logDevice(pkt, hdr->addr3, hdr->addr2);
          }
      }
      // Beacon (8)
      // else if (frameSubtype == 8) {
      //     if (macMatches(hdr->addr3, targetBSSID)) {
      //         // Les beacons peuvent contenir des infos sur les clients connectés
      //         // Mais ici on log juste pour debug
      //         ESP_LOGI(TAG, "Beacon from target AP");
      //     }
      // }
      // // Probe request (4)
      // else if(frameSubtype == 4) {
      //   char ssid[33] = {0};
      //   int ssidLen = extractSSID(pkt->payload, pkt->rx_ctrl.sig_len, ssid);
        
      //   // Only if they're specifically looking for your network (not broadcast)
      //   if (ssidLen > 0 && strcmp(ssid, targetSSID) == 0) {
      //       // Potential device, but not confirmed connected
      //       logDevice(pkt, hdr->addr3, hdr->addr2);
      //   }
      // }
      // // Probe response (5)
      // else if(frameSubtype == 5) {
      //   char ssid[33] = {0};
      //   int ssidLen = extractSSID(pkt->payload, pkt->rx_ctrl.sig_len, ssid);
        
      //   // Only if they're specifically looking for your network (not broadcast)
      //   if (ssidLen > 0 && strcmp(ssid, targetSSID) == 0) {
      //       // Potential device, but not confirmed connected
      //       logDevice(pkt, hdr->addr3, hdr->addr2);
      //   }
      // }
  }
  else if(frameType == 2) { // Data
    // Check if BSSID matches target network
    if(strlen(targetBSSID) > 0) {
      // For ToDS frames: addr1 is BSSID (client -> AP)
      // For FromDS frames: addr2 is BSSID (AP -> client)
      bool toDS = (frameCtrl & 0x0100);
      bool fromDS = (frameCtrl & 0x0200);
      
      uint8_t *bssid = NULL;
      uint8_t *clientMAC = NULL;
      
      if (toDS && !fromDS) {
          // Client to AP
          bssid = hdr->addr1;
          clientMAC = hdr->addr2;

          // char tempMAC[18];
          // macToString(clientMAC, tempMAC);
          // ESP_LOGI(TAG, "ToDS frame - Client MAC: %s", tempMAC);
      } else if (!toDS && fromDS) {
          // AP to Client
          bssid = hdr->addr2;
          clientMAC = hdr->addr1;

          // char tempMAC[18];
          // macToString(clientMAC, tempMAC);
          // ESP_LOGI(TAG, "FromDS frame - Client MAC: %s", tempMAC);
      } else {
          // ESP_LOGI(TAG, "WDS/AdHoc frame - toDS:%d fromDS:%d", toDS, fromDS);
          return; // WDS or adhoc, skip
      }

      // Filter multicast/broadcast
      // if (clientMAC[0] & 0x01) {
      //     return;
      // }

      if(!macMatches(bssid, targetBSSID)) {
        return;
      }

      // static uint32_t dataPacketCount = 0;
      // dataPacketCount++;
      
      // char tempMAC[18];
      // macToString(clientMAC, tempMAC);
      // ESP_LOGI(TAG, "Data frame #%lu - Client: %s [ToDS:%d FromDS:%d]", 
      //        dataPacketCount, tempMAC, toDS, fromDS);

      logDevice(pkt, bssid, clientMAC);
    }
  }
  else {
    return;
  }

  



  
  // Show SSID for beacons/probe responses
  // if (frameSubtype == 8 || frameSubtype == 5) {
  //     char ssid[33] = {0};
  //     if (extractSSID(pkt->payload, pkt->rx_ctrl.sig_len, ssid) > 0) {
  //         ESP_LOGI(TAG, "  SSID: %s", ssid);
  //     }
  // }
}

bool setWifiParameters(const char *ssid, const char *bssid, int channel){
    // Validate channel
    if (channel < 1 || channel > 13) {
        ESP_LOGE(TAG, "Invalid channel: %d", channel);
        return false;
    }

    // ESP_LOGI(TAG,"Channel: %d", channel);

    // Copy SSID (optional)
    if (ssid && ssid[0] != '\0') {
        strncpy(targetSSID, ssid, sizeof(targetSSID) - 1);
        targetSSID[sizeof(targetSSID) - 1] = '\0';
    } else {
        targetSSID[0] = '\0';
    }

    // Copy BSSID (optional)
    if (bssid && bssid[0] != '\0') {
        if (strlen(bssid) != 17) {
            ESP_LOGE(TAG, "Invalid BSSID format: %s", bssid);
            return false;
        }
        for (int i = 0; i < 17 && bssid[i] != '\0'; i++) {
            char c = bssid[i];
            if (c >= 'a' && c <= 'f') {
                targetBSSID[i] = c - 32;  // Convert to uppercase
            } else {
                targetBSSID[i] = c;
            }
        }
        targetBSSID[17] = '\0';
    } else {
        targetBSSID[0] = '\0';
    }

    targetChannel = channel;

    ESP_LOGI(TAG,
        "WiFi params set: SSID='%s', BSSID='%s', CH=%d",
        targetSSID,
        targetBSSID,
        targetChannel
    );

    return true;
}


bool startWiFiSniffer(const char *ssid, const char *bssid, int channel)
{
    if (snifferActive) {
        ESP_LOGW(TAG, "Sniffer already running");
        return false;
    }

    if (!setWifiParameters(ssid, bssid, channel)) {
        ESP_LOGE(TAG, "Sniffer start aborted (bad parameters)");
        return false;
    }

    esp_err_t err;

    err = esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set channel: %s", esp_err_to_name(err));
        return false;
    }

    err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to enable promiscuous: %s", esp_err_to_name(err));
        return false;
    }

    BleManager_SendStatus("LOG|SNIFF|msg=SNIFF_STARTED");
    isAttackActive = true;
    snifferActive = true;
    lastStatsTime = esp_timer_get_time() / 1000;

    ESP_LOGI(TAG, "WiFi Sniffer STARTED");
    return true;
}

void stopWiFiSniffer() {
  if (!snifferActive) return;

  esp_wifi_set_promiscuous(false);
  snifferActive = false;

  ESP_LOGI(TAG, "WiFi Sniffer STOPPED");
}

void onBleDisconnect() {
    stopWiFiSniffer();
    stop_deauth_attack();
    reset_mac();
    isAttackActive = false;
    memset(targetBSSID, 0, sizeof(targetBSSID));
    memset(targetSSID, 0, sizeof(targetSSID));
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

void reset_wifi_stats_variables() {
  lastStatsTime = 0;
  totalPackets = 0;
  filteredPackets = 0;
  ESP_LOGI(TAG, "WIFI stat varibles have been reset");
  BleManager_SendStatus("WIFI_STATS_VARIBLES_RESET");
}

// WIFI intialization
void WifiManager_Init() {

  ESP_LOGI(TAG, "Initializing WiFi Sniffer...");
  // ESP_LOGI(TAG, "Target SSID: %s", targetSSID);
  // ESP_LOGI(TAG, "Target BSSID: %s", targetBSSID);
  // ESP_LOGI(TAG, "Channel: %d", targetChannel);

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