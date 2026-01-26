#ifndef DEAUTH_ATTACK_H
#define DEAUTH_ATTACK_H

#include <stdint.h>

// Start deauth attack
void start_deauth_attack(char *target, char *ap, int channel);

// Stop deauth attack
void stop_deauth_attack();

// Update target AP and client MACs
void set_deauth_targets(const uint8_t *ap, const uint8_t *client);

// Set channel for deauth attack
void set_deauth_channel(uint8_t channel);

// Launch deauth attack
void send_deauth_packets(const uint8_t *ap_mac, const uint8_t *client_mac);

#endif // DEAUTH_ATTACK_H