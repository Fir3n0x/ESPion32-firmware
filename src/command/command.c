#include "command.h"

static const char* TAG = "CommandManager";

bool isValidMac(char *mac) {
    if (!mac) return false;
    if (strlen(mac) != 17) return false;

    for (int i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            // positions 2,5,8,11,14 must be ':'
            if (mac[i] != ':') return false;
        } else {
            // hex
            if (!isxdigit((unsigned char)mac[i])) return false;
        }
    }
    return true;
}

void mac_to_uppercase(char *mac) {
    if (!mac) return;

    for (int i = 0; mac[i]; i++) {
        if (mac[i] >= 'a' && mac[i] <= 'f') {
            mac[i] = mac[i] - ('a' - 'A');
        }
    }
}

void handle_command(char *cmd_raw) {
    char cmd[384];
    strncpy(cmd, cmd_raw, sizeof(cmd) - 1);
    cmd[sizeof(cmd)-1] = '\0';

    char *type = strtok(cmd, "|");

    if(!type) {
        ESP_LOGW(TAG, "Invalid command format [type]");
        BleManager_SendStatus("BAD_FORMAT");
        return;
    }

    // IF RESET_ALL TYPE SKIP THE REST FOR EXAMPLE WHEN SWITCHING NETWORK
    if(strcmp(type, "RESET_ALL") == 0) {
        // Reset all variables

        return;
    }

    // Retrieve action parameter (START/STOP)
    char *action = strtok(NULL, "|");
    
    if(!action) {
        ESP_LOGW(TAG, "Invalid command format [action]");
        BleManager_SendStatus("BAD_FORMAT");
        return;
    }

    if(strcmp(type, "SNIFF") == 0) {
        handle_sniff_command(action);
    }
    else if(strcmp(type, "DEAUTH") == 0) {
        handle_deauth_command(action);
    }
    else if(strcmp(type, "BEACON") == 0) {
        handle_beacon_command(action);
    }
    else if(strcmp(type, "EVILTWIN") == 0) {
        handle_eviltwin_command(action);
    }
    else if(strcmp(type, "MAC") == 0) {
        handle_mac_command(action);
    }
    else if(strcmp(type, "WIFI") == 0) {
        handle_wifi_command(action);
    }
    else {
        ESP_LOGW(TAG, "Unknown command type: %s", type);
        BleManager_SendStatus("UNKNOWN_CMD");
    }
}

void handle_sniff_command(char *action){
    if (strcmp(action, "START") == 0) {

        char *param1_ssid = strtok(NULL, "|");
        char *param2_bssid = strtok(NULL, "|");
        char *param3_channel = strtok(NULL, "|");

        char ssid[96];
        char bssid[18] = {0};
        int channel = -1;

        if (param1_ssid && strncmp(param1_ssid, "SSID=", 5) == 0) {
            strncpy(ssid, param1_ssid + 5, sizeof(ssid) -1);
            ssid[sizeof(ssid)-1] = '\0';
        }

        if (param2_bssid && strncmp(param2_bssid, "BSSID=", 6) == 0) {
            strncpy(bssid, param2_bssid + 6, sizeof(bssid) - 1);
        }

        if (param3_channel && strncmp(param3_channel, "CHANNEL=", 8) == 0) {
            channel = atoi(param3_channel + 8);
        }

        if (strlen(bssid) == 0 || channel <= 0) {
            ESP_LOGW(TAG, "Missing SNIFF params");
            BleManager_SendStatus("LOG|SNIFF|msg=SNIFF_BAD_PARAMS");
            return;
        }

        if(!snifferActive) {
            ESP_LOGI(TAG, "Starting sniffer: SSID = %s, BSSID=%s, CHANNEL=%d", ssid, bssid, channel);
            startWiFiSniffer(ssid, bssid, channel);
        } else{
            BleManager_SendStatus("LOG|SNIFF|msg=SNIFF_ALREADY_RUNNING");
        }
    }

    else if (strcmp(action, "STOP") == 0) {
        ESP_LOGI(TAG, "Stopping sniffer");
        isAttackActive = false;
        stopWiFiSniffer();
        BleManager_SendStatus("LOG|SNIFF|msg=SNIFF_STOPPED");
    }

    else {
        ESP_LOGW(TAG, "Unknown SNIFF action: %s", action);
        BleManager_SendStatus("LOG|SNIFF|msg=SNIFF_UNKNOWN_ACTION");
    }
}


void handle_deauth_command(char *action) {
    if (strcmp(action, "START") == 0) {

        char *param1_targetMac = strtok(NULL, "|");
        char *param2_apMac = strtok(NULL, "|");
        char *param3_ch = strtok(NULL, "|");

        char target[18] = {0};
        char ap[18] = {0};
        int channel = -1;

        if (param1_targetMac && strncmp(param1_targetMac, "TARGET=", 7) == 0) {
            strncpy(target, param1_targetMac + 7, sizeof(target) - 1);
        }

        if (param2_apMac && strncmp(param2_apMac, "AP=", 3) == 0) {
            strncpy(ap, param2_apMac + 3, sizeof(ap) - 1);
        }

        if (param3_ch && strncmp(param3_ch, "CHANNEL=", 8) == 0) {
            channel = atoi(param3_ch + 8);
        }

        if (!target[0] || !ap[0] || channel <= 0) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_BAD_PARAMS");
            return;
        }

        // Set to uppercase
        mac_to_uppercase(target);
        mac_to_uppercase(ap);

        // Verify mac target
        if (!isValidMac(target)) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_BAD_TARGET_MAC");
            return;
        }

        // Verify mac AP
        if (!isValidMac(ap)) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_BAD_AP_MAC");
            return;
        }

        if(!deauthActive) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_INITIALIZING...");
            vTaskDelay(pdMS_TO_TICKS(500));
            start_deauth_attack(target, ap, channel);
        } else{
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_ALREADY_RUNNING");
        }
    }
    else if(strcmp(action, "TEST") == 0) {
        char *param1_targetMac = strtok(NULL, "|");
        char *param2_apMac = strtok(NULL, "|");
        char *param3_ch = strtok(NULL, "|");

        char target[18] = {0};
        char ap[18] = {0};
        int channel = -1;

        if (param1_targetMac && strncmp(param1_targetMac, "TARGET=", 7) == 0) {
            strncpy(target, param1_targetMac + 7, sizeof(target) - 1);
        }

        if (param2_apMac && strncmp(param2_apMac, "AP=", 3) == 0) {
            strncpy(ap, param2_apMac + 3, sizeof(ap) - 1);
        }

        if (param3_ch && strncmp(param3_ch, "CHANNEL=", 8) == 0) {
            channel = atoi(param3_ch + 8);
        }

        if (!target[0] || !ap[0] || channel <= 0) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_BAD_PARAMS");
            return;
        }

        // Set to uppercase
        mac_to_uppercase(target);
        mac_to_uppercase(ap);

        // Verify mac target
        if (!isValidMac(target)) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_BAD_TARGET_MAC");
            return;
        }

        // Verify mac AP
        if (!isValidMac(ap)) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_BAD_AP_MAC");
            return;
        }

        if(!deauthActive && !snifferActive) {
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_TEST_INITIALIZING...");
            vTaskDelay(pdMS_TO_TICKS(500));
            start_deauth_with_effectiveness_test(target, ap, channel);
        } else{
            BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_ALREADY_RUNNING");
        }
    }
    else if (strcmp(action, "STOP") == 0) {
        isAttackActive = false;
        stop_deauth_attack();
        BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_STOPPED");
    }
    else {
        ESP_LOGW(TAG, "Unknown DEAUTH action: %s", action);
        BleManager_SendStatus("LOG|DEAUTH|msg=DEAUTH_UNKNOWN_ACTION");
    }
}


void handle_beacon_command(char *action) {
    if(strcmp(action, "START") == 0) {

        char* param1_channel = strtok(NULL, "|");
        char* param2_ssids = strtok(NULL, "|");

        int channel = -1;
        char ssids_raw[384] = {0};

        if(param1_channel && strncmp(param1_channel, "CHANNEL=", 8) == 0) {
            channel = atoi(param1_channel + 8);
        }

        if(param2_ssids && strncmp(param2_ssids, "SSIDS=", 6) == 0) {
            strncpy(ssids_raw, param2_ssids + 6, sizeof(ssids_raw) -1);
        }

        if(channel <= 0 || strlen(ssids_raw) == 0) {
            ESP_LOGW(TAG, "channel=%d, strlen(ssids_raw)=%d", channel, strlen(ssids_raw));
            BleManager_SendStatus("LOG|BEACON|msg=BEACON_BAD_PARAMS");
            return;
        }

        // Parse SSIDs separated by ~
        char *ssid_list[MAX_SSID_BEACON]; // Max SSIDs
        int ssid_count = 0;

        char *token = strtok(ssids_raw, "~");
        while(token != NULL && ssid_count < MAX_SSID_BEACON){
            ssid_list[ssid_count++] = token;
            token = strtok(NULL, "~");
        }

        if(!bfsActive) {
            start_beacon_spam(channel, ssid_list, ssid_count);
        } else {
            BleManager_SendStatus("LOG|BEACON|msg=BFS_ALREADY_RUNNING");
        }

    }
    else if(strcmp(action, "STOP") == 0) {
        ESP_LOGI(TAG, "Stopping beacon spam");
        isAttackActive = false;
        stop_beacon_spam();
        BleManager_SendStatus("LOG|BEACON|msg=BEACON_STOPPED");
    }
    else {
        ESP_LOGW(TAG, "Unknown BEACON action: %s", action);
        BleManager_SendStatus("LOG|BEACON|msg=BEACON_UNKNOWN_ACTION");
    }
}

void handle_eviltwin_command(char* action) {
    if(strcmp(action, "START") == 0) {

        char* param1_method = strtok(NULL, "|");
        char* param2_name = strtok(NULL, "|");

        int method = -1;
        char name[30] = {0};

        if(param1_method && strncmp(param1_method, "METHOD=", 7) == 0) {
            method = atoi(param1_method + 7);
        }

        if(param2_name && strncmp(param2_name, "NAME=", 5) == 0) {
            strncpy(name, param2_name + 5, sizeof(name) -1);
        }

        // start_eviltwin(method, name);

    } else if(strcmp(action, "STOP") == 0) {
        ESP_LOGI(TAG, "Stopping evil twin");
        isAttackActive = false;
        // stop_eviltwin();
        BleManager_SendStatus("LOG|EVILTWIN|msg=EVILTWIN_STOPPED");
    }else {
        ESP_LOGW(TAG, "Unknown EVILTWIN action: %s", action);
        BleManager_SendStatus("LOG|EVILTWIN|msg=EVILTWIN_UNKNOWN_ACTION");
    }
}

void handle_mac_command(char *action) {
    if(strcmp(action, "CLEAR") == 0) {
        ESP_LOGI(TAG, "MAC will be cleared");
        reset_mac();
    } else {
        ESP_LOGW(TAG, "Bad Command for MAC type");
        BleManager_SendStatus("MAC_UNKNOWN_ACTION");
    }
}

// Reset wifi variables (stats...)
void handle_wifi_command(char *action) {
    if(strcmp(action, "CLEAR") == 0) {
        ESP_LOGI(TAG, "WIFI stat variables will be reset");
        reset_wifi_stats_variables();
    } else {
        ESP_LOGW(TAG, "Bad Command for WIFI type");
        BleManager_SendStatus("WIFI_UNKNOWN_ACTION");
    }
}