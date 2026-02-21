#ifndef CLASSIC_DEAUTH_H
#define CLASSIC_DEAUTH_H

#include "attacks/deauth/Deauth.h"

#include <stdint.h>
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_coexist.h"
#include "esp_bt.h"
#include "esp_timer.h"


//attacks
void send_deauth_packets(const uint8_t *ap_mac, const uint8_t *client_mac); // Launch deauth attack
void start_deauth_attack(char *target, char *ap, int channel); // Start deauth attack
void stop_deauth_attack(); // Stop deauth attack

#endif