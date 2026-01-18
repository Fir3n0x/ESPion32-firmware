#ifndef BLINK_H
#define BLINK_H

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "common/SharedState.h"

#define BLINK_GPIO 2

void blink_init();
void bleClientConnected();
void bleClientDisconnected();
void receiveCommandBlink();
void attackInProgress(void *pvParameters);

#endif