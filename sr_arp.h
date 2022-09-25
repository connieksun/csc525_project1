/*-----------------------------------------------------------------------------
 * File: sr_arp.h
 *---------------------------------------------------------------------------*/

#ifndef SR_ARP_H
#define SR_ARP_H
#include "sr_router.h"

/* -- sr_arp.c -- */
void sr_handle_arp_request(struct sr_instance*, uint8_t*, struct sr_arphdr*);
void sr_handle_arp_reply(struct sr_instance*, uint8_t*);
void sr_send_arp_request();
void sr_send_arp_reply();
void add_entry_to_cache(struct sr_instance*, struct sr_arp_cache*);

void print_rt_ip(struct sr_instance*);
void print_if_ip(struct sr_instance*);

// represents a LL of cache entries. Will be attached to sr_instance of our router
struct sr_arp_cache {
	unsigned char* phys_addr[ETHER_ADDR_LEN];
	uint32_t ip_addr;
	time_t time_added;
	struct sr_arp_cache* prev;
	struct sr_arp_cache* next;
};

#endif /* SR_ARP_H */
