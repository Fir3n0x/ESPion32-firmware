#include "SharedState.h"

volatile bool snifferActive = false;
volatile uint32_t totalPackets = 0;
volatile uint32_t filteredPackets = 0;
volatile QueueHandle_t macQueue = NULL;
volatile bool isAttackActive = false;