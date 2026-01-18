#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include <esp_wifi.h>
#include <stdbool.h>

void WifiManager_Init(void);
void startWiFiSniffer(void);
void stopWiFiSniffer(void);
void printWiFiStats(void);
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);

#endif