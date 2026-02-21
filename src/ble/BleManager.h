#ifndef BLE_MANAGER_H
#define BLE_MANAGER_H

#include "common/SharedState.h"
#include "wifi/WifiManager.h"
#include "attacks/deauth/Deauth.h"
#include "blinking/blink.h"
#include "command/command.h"
#include "wifi/WifiManager.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include "esp_gatt_common_api.h"

void BleManager_Init();
void BleManager_SendStatus(const char *msg);
void bleSenderTask(void* param);
void reset_mac();
void reset_wifi_stats_variables();

#endif // BLE_MANAGER_H