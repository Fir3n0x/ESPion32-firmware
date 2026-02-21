#ifndef COMMAND_H
#define COMMAND_H

#include "common/SharedState.h"
#include "wifi/WifiManager.h"
#include "attacks/deauth/Deauth.h"
#include "attacks/deauth/classic_deauth.h"
#include "attacks/deauth/test_deauth.h"
#include "attacks/deauth/steal_deauth.h"
#include "attacks/bfs/BFS.h"
#include "ble/BleManager.h"

#include <string.h>
#include <ctype.h>
#include "esp_wifi.h"
#include "esp_log.h"

void handle_command(char *cmd_raw);
void handle_sniff_command(char *action);
void handle_deauth_command(char *action);
void handle_beacon_command(char *action);
void handle_eviltwin_command(char* action);
void handle_mac_command(char *action);
void handle_wifi_command(char *action);

#endif