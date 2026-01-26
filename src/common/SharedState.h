#ifndef SHARED_STATE_H
#define SHARED_STATE_H

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t mac[6];
    int8_t rssi;
    uint8_t channel;
} mac_event_t;

extern volatile bool snifferActive;
extern volatile bool deauthActive;
extern volatile uint32_t totalPackets;
extern volatile uint32_t filteredPackets;
extern volatile QueueHandle_t macQueue;
extern volatile bool isAttackActive;

#endif