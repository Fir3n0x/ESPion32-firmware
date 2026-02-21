#ifndef TEST_DEAUTH_H
#define TEST_DEAUTH_H

#include "common/SharedState.h"
#include "attacks/deauth/Deauth.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include <stdint.h>
#include <stdbool.h>

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

// Launch timed deauth attack
void send_deauth_packets_timed(const uint8_t *ap_mac, const uint8_t *client_mac, uint32_t duration_ms);

// Deauth attack test with efficiency test
void start_deauth_with_effectiveness_test(char *target, char *ap, int channel);

#endif