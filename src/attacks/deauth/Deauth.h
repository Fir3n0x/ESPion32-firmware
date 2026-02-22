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

// Deauth frame template
extern const uint8_t deauth_frame[26];

//getter
uint8_t deauth_get_attack_channel(void);
const uint8_t* deauth_get_ap_target(void);
const uint8_t* deauth_get_client_target(void);
TaskHandle_t deauth_get_task_handle(void);

//setter
void set_deauth_targets(const uint8_t *ap, const uint8_t *client); // Update target AP and client MACs
void set_deauth_channel(uint8_t channel); // Set channel for deauth attack
void deauth_set_task_handle(TaskHandle_t dth);

//deauth manager
void prepare_for_injection(void);
void restore_wifi_state(void);
void configure_ble_coexistence(void);

//during attack
void build_deauth_packet(uint8_t *packet, const uint8_t *dst, const uint8_t *src, const uint8_t *bssid, uint8_t reason);
esp_err_t send_with_retry(const uint8_t *packet, int max_retries);

//utility
bool mac_str_to_bytes(const char *mac_str, uint8_t *mac_bytes);
uint16_t deauth_next_seq(void); // getter seq number shared

#endif // DEAUTH_H