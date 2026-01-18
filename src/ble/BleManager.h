#ifndef BLE_MANAGER_H
#define BLE_MANAGER_H

#include "wifi/WifiManager.h"

void BleManager_Init();
void BleManager_SendStatus(const char *msg);
void bleSenderTask(void* param);

#endif // BLE_MANAGER_H