#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include <esp_wifi.h>
#include <stdbool.h>

void WifiManager_Init(void);
bool setWifiParameters(const char *ssid, const char *bssid, int channel);
bool startWiFiSniffer(const char *ssid, const char *bssid, int channel);
void stopWiFiSniffer(void);
void printWiFiStats(void);
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);

#endif