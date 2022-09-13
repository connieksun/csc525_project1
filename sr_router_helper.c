#include <inttypes.h>
#include "sr_protocol.h"
/*
 * This file defines helper methods for sr_router.c
 */

uint16_t checksum(uint16_t *buf, int len){
	unsigned long sum = 0;
	while (len--){
		sum += *buf++;
		if (sum & 0xFFFF0000){
			sum &= 0xFFFF;
			sum++;
		}
	}
	return ~(sum & 0xFFFF);
}
