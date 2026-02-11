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

#endif // DEAUTH_H