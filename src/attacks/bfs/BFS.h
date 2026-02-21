#ifndef BFS_H
#define BFS_H

#include "common/SharedState.h"

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_coexist.h"
#include "esp_bt.h"
#include "esp_timer.h"

#define MAX_SSID_BEACON 20
#define MAX_SSID_LEN 20

void bfs_attack(int channel);
void start_beacon_spam(int channel, char** ssid_list, int ssid_count);
void stop_beacon_spam();
void set_bfs_channel(const uint8_t channel);
void set_bfs_ssid_list(char** ssid_list, int ssid_count);


#endif