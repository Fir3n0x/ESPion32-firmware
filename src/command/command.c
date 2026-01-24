#include "command.h"

static const char* TAG = "CommandManager";

void handle_command(char *cmd_raw) {

    char cmd[128];
    strncpy(cmd, cmd_raw, sizeof(cmd) - 1);
    cmd[sizeof(cmd)-1] = '\0';

    char *type = strtok(cmd, "|");
    char *action = strtok(NULL, "|");
    
    if(!type || !action) {
        ESP_LOGW(TAG, "Invalid command format");
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
        char *ssid = strtok(NULL, "|");
        char *channel = strtok(NULL, "|");
        handle_beacon_command(action, ssid, channel);
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
            BleManager_SendStatus("SNIFF_BAD_PARAMS");
            return;
        }

        ESP_LOGI(TAG, "Starting sniffer: SSID = %s, BSSID=%s, CHANNEL=%d", ssid, bssid, channel);

        isAttackActive = true;
        startWiFiSniffer(ssid, bssid, channel);
        BleManager_SendStatus("SNIFF_STARTED");
    }

    else if (strcmp(action, "STOP") == 0) {
        ESP_LOGI(TAG, "Stopping sniffer");
        isAttackActive = false;
        stopWiFiSniffer();
        BleManager_SendStatus("SNIFF_STOPPED");
    }

    else {
        ESP_LOGW(TAG, "Unknown SNIFF action: %s", action);
        BleManager_SendStatus("SNIFF_UNKNOWN_ACTION");
    }
}


void handle_deauth_command(char *action) {
    // if (strcmp(action, "START") == 0) {

        // char *param1 = strtok(NULL, "|");
        // char *param2 = strtok(NULL, "|");
        // char *param3 = strtok(NULL, "|");

    //     char target[18] = {0};
    //     char ap[18] = {0};
    //     int channel = -1;

    //     if (param1 && strncmp(param1, "TARGET=", 7) == 0) {
    //         strncpy(target, param1 + 7, sizeof(target) - 1);
    //     }

    //     if (param2 && strncmp(param2, "AP=", 3) == 0) {
    //         strncpy(ap, param2 + 3, sizeof(ap) - 1);
    //     }

    //     if (param3 && strncmp(param3, "CHANNEL=", 8) == 0) {
    //         channel = atoi(param3 + 8);
    //     }

    //     if (!target[0] || !ap[0] || channel <= 0) {
    //         BleManager_SendStatus("DEAUTH_BAD_PARAMS");
    //         return;
    //     }

    //     isAttackActive = true;
    //     start_deauth_attack(target, ap, channel);
    //     BleManager_SendStatus("DEAUTH_OK");
    // }

    // else if (strcmp(action, "STOP") == 0) {
    //     isAttackActive = false;
    //     stop_deauth_attack();
    //     BleManager_SendStatus("DEAUTH_STOPPED");
    // }
}


void handle_beacon_command(char *action, char *param1, char *param2) {
    return;
}