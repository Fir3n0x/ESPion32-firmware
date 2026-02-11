#include "WifiManager.h"


static const char* TAG = "WifiManager";


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


void onBleDisconnect() {
    stopWiFiSniffer();
    stop_deauth_attack();
    reset_mac();
    isAttackActive = false;
    memset(targetBSSID, 0, sizeof(targetBSSID));
    memset(targetSSID, 0, sizeof(targetSSID));
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