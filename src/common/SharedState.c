#include "SharedState.h"

volatile bool snifferActive = false;
volatile bool deauthActive = false;
volatile uint32_t totalPackets = 0;
volatile uint32_t filteredPackets = 0;
volatile QueueHandle_t macQueue = NULL;
// for BLE blinking
volatile bool isAttackActive = false;