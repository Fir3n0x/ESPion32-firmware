#include "SharedState.h"

volatile bool snifferActive = false;
volatile bool deauthActive = false;
volatile bool captureActive = false;
volatile bool bfsActive = false;
volatile uint32_t totalPackets = 0;
volatile uint32_t filteredPackets = 0;
volatile QueueHandle_t macQueue = NULL;
volatile bool isAttackActive = false; // for BLE blinking
extern volatile char targetSSID[96] = {0}; // Set your target SSID
extern volatile char targetBSSID[18] = {0}; // Specific BSSID
extern volatile uint8_t targetChannel = 1; // WiFi channel (1-13) — défaut valide (évitait 255)