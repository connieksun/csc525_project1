/*-----------------------------------------------------------------------------
 * File: sr_arp.h
 *---------------------------------------------------------------------------*/

#ifndef SR_ARP_H
#define SR_ARP_H

/* -- sr_arp.c -- */
void sr_handle_arp_request(struct sr_instance*, uint8_t*, struct sr_arphdr*);
void sr_handle_arp_reply(struct sr_instance*, uint8_t*);
void sr_send_arp_request();
void sr_send_arp_reply();

void print_rt_ip(struct sr_instance*);
void print_if_ip(struct sr_instance*);

#endif /* SR_ARP_H */