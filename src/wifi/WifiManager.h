#ifndef WIFI_MANAGER_H
#define WIFI_MANAGER_H

#include "common/SharedState.h"
#include "ble/BleManager.h"
#include "attacks/Sniffer.h"
#include "attacks/Deauth.h"

#include <string.h>
#include <stdio.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <esp_wifi.h>
#include <stdbool.h>

void WifiManager_Init(void);
bool setWifiParameters(const char *ssid, const char *bssid, int channel);
void onBleDisconnect();

#endif