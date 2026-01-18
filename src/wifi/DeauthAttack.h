#ifndef DEAUTH_ATTACK_H
#define DEAUTH_ATTACK_H

#include <stdint.h>

// Start deauth attack with specified number of packet bursts
void start_deauth_attack(int packet_count);

// Update target AP and client MACs
void set_deauth_targets(const uint8_t *ap, const uint8_t *client);

// Set channel for deauth attack
void set_deauth_channel(uint8_t channel);

// Test if target has PMF (802.11w) protection
void test_pmf_protection(void);

#endif // DEAUTH_ATTACK_H