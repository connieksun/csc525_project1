#include <inttypes.h>
#include "sr_protocol.h"
/*
 * This file defines helper methods for sr_router.c
 */


/**
 * convert_uint32_to_ip(uint32_t address) takes a uint32_t and converts it to ipv4
 */
void convert_uint32_to_ip(uint32_t address, uint8_t* ip) {
	int x;
	for (x = IPV4_ADDR_LEN - 1; x >= 0; x--) {
		ip[x] = (address >> (x*8)) & (uint8_t) -1;
	}
}
