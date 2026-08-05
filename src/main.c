#include "ble/BleManager.h"
#include "wifi/WifiManager.h"
#include "common/SharedState.h"
#include "blinking/blink.h"

#include <nvs_flash.h>
#include <esp_log.h>
#include <esp_system.h>

static const char *TAG = "Main";

void app_main() {

    // Wait for everything to work
    vTaskDelay(pdMS_TO_TICKS(2000));

    ESP_LOGI(TAG, "ESP32 BLE + WiFi Tool Starting...");
    ESP_LOGI(TAG, "Free heap BEFORE init: %lu bytes", esp_get_free_heap_size());

    // Initialize Blinking setup
    blink_init();
    xTaskCreate(
        attackInProgress,
        "Blinking during attack",
        4096,
        NULL,
        1,
        NULL
    );

    esp_err_t ret;

    // Initialize NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize network interface (required for WiFi)
    ESP_ERROR_CHECK(esp_netif_init());
    
    // Create default event loop (required for WiFi)
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    // Initialize WiFi with default config
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    // Set WiFi mode to Station (required for promiscuous mode)
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    
    // Start WiFi
    ESP_ERROR_CHECK(esp_wifi_start());

    // Désactive le power save : indispensable pour une injection et une
    // capture promiscuous fiables (sinon la radio dort entre les DTIM).
    esp_wifi_set_ps(WIFI_PS_NONE);

    ESP_LOGI(TAG, "WiFi initialized");

    // Create MAC queue
    macQueue = xQueueCreate(100, sizeof(mac_event_t));
    if (macQueue == NULL) {
        ESP_LOGE(TAG, "Failed to create MAC queue");
        return;
    }

    // Initialize WiFi and BLE
    WifiManager_Init();
    BleManager_Init();

    // Handle periodic task with freertos os
    xTaskCreate(
        bleSenderTask,
        "BLE Sender Task",
        4096,
        NULL,
        1,
        NULL
    );

    ESP_LOGI(TAG, "System ready! Connect via BLE to control.");
    ESP_LOGI(TAG, "Free heap: %lu bytes", esp_get_free_heap_size());
}