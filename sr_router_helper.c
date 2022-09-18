#include <inttypes.h>
#include <stddef.h>
#include <sys/time.h>
#include <stdlib.h>
#include "sr_router_helper.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arp.h"

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

struct sr_arp_cache* get_cached_arp_entry(struct sr_instance* sr, uint8_t * p, struct in_addr dst) {
	if (sr->arp_cache == NULL) {
		return NULL;
	}
	struct sr_arp_cache * cache_entry = sr->arp_cache;
	while (cache_entry) {
		if (cache_entry->ip_addr == dst.s_addr) {
			struct timeval * cur_time = malloc(sizeof(struct timeval));
			gettimeofday(cur_time, NULL);
			if (cur_time->tv_sec - cache_entry->time_added > 10) {
				return NULL;
			} else {
				return cache_entry;
			}
		}
		cache_entry = cache_entry->next; 
	}
	return NULL;
}

struct sr_if* get_router_interface(struct sr_instance* sr) {
	return sr->if_list;
}
