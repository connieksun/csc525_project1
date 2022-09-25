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
#include "sr_ip.h"
#include "sr_rt.h"

/*
 * This file defines helper methods for sr_router.c
 */

 
/*----------------------------------------------------------------------------------- 
 * Method: checksum(uint16_t *buf, int len)
 * Scope:  Global
 *
 * This method is used to calculate the checksum of packet headers (IP, ICMP)
 * Used alg. from textbook (Davie, Peterson)
 *
 *----------------------------------------------------------------------------------*/
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


/*----------------------------------------------------------------------------------- 
 * Method: get_cached_arp_entry(struct sr_instance* sr, uint8_t * p, struct in_addr dst)
 * Scope:  Global
 *
 * This method is used to fetch the cached ARP information for a given destination IP.
 * If ARP information for the specified IP is not in our cache, return NULL
 *
 *----------------------------------------------------------------------------------*/
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

// helper method to fetch interface associated with our router + make code more readable
struct sr_if* get_router_interface(struct sr_instance* sr) {
	return sr->if_list;
}

/*----------------------------------------------------------------------------------- 
 * Method: get_best_if_match(struct sr_instance* sr, struct in_addr ip
 * Scope:  Global
 *
 * This method is used when the final destination is not one which belongs to our router.
 * In this case, we must find the nexthop to send it to; the interface with the longest
 * 	prefix match.
 *
 *----------------------------------------------------------------------------------*/
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


/*----------------------------------------------------------------------------------- 
 * Method: get_best_rt_match(struct sr_instance* sr, struct in_addr ip)
 * Scope:  Global
 *
 * This method is used when the final destination is not one which belongs to our router.
 * In this case, we must find the nexthop to send it to; the routing table entry
 *	with the longest prefix match
 *
 *----------------------------------------------------------------------------------*/
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


/*----------------------------------------------------------------------------------- 
 * Method: add_packet_to_buffer(struct sr_instance* sr, uint8_t* packet)
 * Scope:  Global
 *
 * This method is used when we have sent an ARP request for a destination whose
 * 	physical address is unknown, and we don't yet have the reply. Packets will
 *	buffered until the reply is processed; and then they will be processed in order
 *
 *----------------------------------------------------------------------------------*/
void add_packet_to_buffer(struct sr_instance* sr, uint8_t* packet) {
	struct sr_packet_buffer* buf = sr->packet_buffer;
	struct sr_packet_buffer* last_entry = NULL;
	struct sr_packet_buffer* new_entry = malloc(sizeof(struct sr_packet_buffer));
	new_entry->packet = packet;
	new_entry->prev = NULL;
	new_entry->next = NULL;
	if (!buf) { // if there is no buffer, start one
		sr->packet_buffer = new_entry;
		return;
	}
	while (buf) { // else, find the end
		last_entry = buf;
		buf = buf->next;
	}
	last_entry->next = new_entry;
	new_entry->prev = last_entry;
	return;
}

/*----------------------------------------------------------------------------------- 
 * Method: handle_buffered_packets(struct sr_instance* sr, uint32_t ip_addr)
 * Scope:  Global
 *
 * This method is used when we have received an ARP reply and are now able
 * to process the packets whose destination is provided by this ARP reply.
 *	Packets are maintained in this buffer in order, and will be processed in order.
 *  Once processed, the packet will be removed from the buffer. 
 *
 *----------------------------------------------------------------------------------*/
void handle_buffered_packets(struct sr_instance* sr, uint32_t ip_addr) {
	struct sr_packet_buffer* buf = sr->packet_buffer;
	struct sr_packet_buffer* prev = NULL;
	while (buf) {
		uint8_t* p = buf->packet;
		struct ip* ip_hdr = (struct ip*) (p + sizeof(struct sr_ethernet_hdr));
		if (ip_hdr->ip_dst.s_addr == ip_addr) {
			if (!prev) { // if this was the first packet in buffer, set beginning of buffer to second elem
				sr->packet_buffer = buf->next; // could be NULL, this is OK
			} else if (!buf->next) { // if this was the last packet in buf
				prev->next = NULL; // remove
			} else { // if the packet was anywhere in the middle, update pointers
				buf->next->prev = buf->prev;
				buf->prev->next = buf->next;
			}
			sr_handle_ip(sr, p, ip_hdr); // process the packet
			free(buf);
		}
		prev = buf;
		buf = buf->next;
	}
}

/*----------------------------------------------------------------------------------- 
 * Method: packets_for_ip_are_buffered(struct sr_instance* sr, uint32_t ip_addr)
 * Scope:  Global
 *
 * This method is used to check if there are packets already buffered for this 
 * 	destination IP address. If there are, to maintain order, we must add a packet
 *  to the buffer instead of forwarding it along. 
 *
 *----------------------------------------------------------------------------------*/
int packets_for_ip_are_buffered(struct sr_instance* sr, uint32_t ip_addr) {
	struct sr_packet_buffer* buf = sr->packet_buffer;
	while (buf) {
		uint8_t* p = buf->packet;
		struct ip* ip_hdr = (struct ip*) (p + sizeof(struct sr_ethernet_hdr));
		if (ip_hdr->ip_dst.s_addr == ip_addr) {
			return 1;
		}
		buf = buf->next;
	}
	return 0;
}