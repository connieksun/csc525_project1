#include <inttypes.h>
#include <stddef.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include "sr_router_helper.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_arp.h"
#include "sr_if.h"
#include "sr_rt.h"

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
				free(cur_time);
				return NULL;
			} else {
				free(cur_time);
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

struct sr_if* get_best_if_match(struct sr_instance* sr, struct in_addr ip) {
	char best_if[SR_IFACE_NAMELEN];
	best_if[0] = 0;
	struct in_addr best_ip;
	struct sr_rt* rout_table = sr->routing_table;
	while (rout_table) { // search all locations to send
		if ((ip.s_addr && rout_table->mask.s_addr) == (rout_table->dest.s_addr && rout_table->mask.s_addr)) { // if we have a match
			if (!best_if[0]) { // if no previous match, set match
				best_ip = rout_table->dest;
				memcpy(best_if, rout_table->interface, SR_IFACE_NAMELEN);
			} else { // else if we do have a match already
				if (abs(best_ip.s_addr - ip.s_addr) > abs(rout_table->dest.s_addr - ip.s_addr)) { // see if it's a better match
					best_ip = rout_table->dest;
					memcpy(best_if, rout_table->interface, SR_IFACE_NAMELEN); // update
				}
			}
		}
		rout_table = rout_table->next;
	}
	return sr_get_interface(sr, best_if); // return interface corresponding to our chosen dest
}

struct sr_rt* get_best_rt_match(struct sr_instance* sr, struct in_addr ip) {
	char best_if[SR_IFACE_NAMELEN];
	best_if[0] = 0;
	struct sr_rt* best_route = NULL;
	struct in_addr best_ip;
	struct sr_rt* rout_table = sr->routing_table;
	while (rout_table) { // search all locations to send
		if ((ip.s_addr && rout_table->mask.s_addr) == (rout_table->dest.s_addr && rout_table->mask.s_addr)) { // if we have a match
			if (!best_if[0]) { // if no previous match, set match
				best_route = rout_table;
				best_ip = rout_table->dest;
				memcpy(best_if, rout_table->interface, SR_IFACE_NAMELEN);
			} else { // else if we do have a match already
				if (abs(best_ip.s_addr - ip.s_addr) > abs(rout_table->dest.s_addr - ip.s_addr)) { // see if it's a better match
					best_route = rout_table;
					best_ip = rout_table->dest;
					memcpy(best_if, rout_table->interface, SR_IFACE_NAMELEN); // update
				}
			}
		}
		rout_table = rout_table->next;
	}
	return best_route; // return route corresponding to our chosen dest
}

