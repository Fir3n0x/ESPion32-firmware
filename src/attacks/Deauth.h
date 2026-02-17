#ifndef DEAUTH_H
#define DEAUTH_H

#include "common/SharedState.h"
#include "ble/BleManager.h"
#include "wifi/wsl_bypasser/wsl_bypasser.h"

#include <stdint.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_coexist.h"
#include "esp_bt.h"
#include "esp_timer.h"

// Struct for stat effectiveness
typedef struct {
    uint32_t deauth_sent;
    uint32_t auth_baseline;
    uint32_t auth_post_attack;
    uint32_t reassoc_post_attack;
    uint32_t probe_req_post_attack;
    uint32_t deauth_post_attack;
    bool likely_successful;
    float effectiveness_score;
} deauth_effectiveness_t;

// Start deauth attack
void start_deauth_attack(char *target, char *ap, int channel);

// Stop deauth attack
void stop_deauth_attack();

// Update target AP and client MACs
void set_deauth_targets(const uint8_t *ap, const uint8_t *client);

// Set channel for deauth attack
void set_deauth_channel(uint8_t channel);

// Launch deauth attack
void send_deauth_packets(const uint8_t *ap_mac, const uint8_t *client_mac);

// Launch timed deauth attack
void send_deauth_packets_timed(const uint8_t *ap_mac, const uint8_t *client_mac, uint32_t duration_ms);

// Deauth attack test with efficiency test
void start_deauth_with_effectiveness_test(char *target, char *ap, int channel);

#endif // DEAUTH_H