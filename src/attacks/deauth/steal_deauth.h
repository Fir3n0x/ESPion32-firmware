#ifndef STEAL_DEAUTH_H
#define STEAL_DEAUTH_H

#include "common/SharedState.h"
#include "attacks/deauth/Deauth.h"

#include "stdint.h"
#include <string.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_coexist.h"
#include "esp_bt.h"
#include "esp_timer.h"

// attacks
void start_deauth_steal_attack(char *target, char *ap, int channel);
void stop_deauth_steal_attack();

#endif