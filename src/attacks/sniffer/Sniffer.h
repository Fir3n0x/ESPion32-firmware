#ifndef SNIFFER_H
#define SNIFFER_H

#include "common/SharedState.h"
#include "wifi/WifiManager.h"

#include <esp_wifi.h>
#include <esp_log.h>
#include <stdbool.h>


bool startWiFiSniffer(const char *ssid, const char *bssid, int channel);
void stopWiFiSniffer(void);
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void printWiFiStats(void);
void reset_wifi_stats_variables();


#endif