/**********************************************************************
 * file:  sr_ip.c 
 *
 * Description:
 * 
 * This file contains functions to handle IP forwarding (and ICMP)
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_router_helper.h"
#include "sr_ip.h"
#include "sr_arp.h"

/*--------------------------------------------------------------------- 
 * Method: get_interface_dst(struct sr_instance* sr, struct in_addr dst) 
 * Scope:  Global
 *
 * This method is called when we are sending a packet to a known IP. 
 *  Returns the interface associated with that IP. 
 *
 *---------------------------------------------------------------------*/
struct sr_if* get_interface_dst(struct sr_instance* sr, struct in_addr dst) {
    struct sr_if *interface = sr->if_list;
    while (interface){
        if (interface->ip == dst.s_addr) return interface;
        interface = interface->next;
    }
    return NULL;
}

/*--------------------------------------------------------------------- 
 * Method: sr_handle_ip() 
 * Scope:  Global
 *
 * This method is called when the received packet is IP
 *  If IP packet destination is one of the router's interfaces, we handle
 *      the packet here. Else, we must forward it to its dest.
 *
 *---------------------------------------------------------------------*/
void sr_handle_ip(struct sr_instance* sr,
                            uint8_t* p,
                            struct ip* ip_hdr){
    // printf("*** handle ip\n");
    struct in_addr dst = ip_hdr->ip_dst;
    struct sr_if* router_if_match = get_interface_dst(sr, dst); // to be used if dest is one of our router/repeater
    if (router_if_match) { // if destination is local, we handle IP here
       sr_handle_icmp(sr, p, ip_hdr, router_if_match);
    } else {  // must forward along
        //printf("  destination is not router\n");
        struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*) p;
        struct sr_rt* best_route = get_best_rt_match(sr, dst); // find which route to send a long
        struct sr_if* next_hop_if = sr_get_interface(sr, best_route->interface); // get if associated with route
        memcpy(eth_hdr->ether_shost, next_hop_if->addr, ETHER_ADDR_LEN); 

        struct sr_arp_cache * arp_entry = get_cached_arp_entry(sr, p, dst);
        if (arp_entry == NULL) { // if we don't know where to send it
            //printf("      ARP val was not in cache\n");
            sr_send_arp_request(sr, p, ip_hdr); // send arp request
            add_packet_to_buffer(sr, p); // buffer packet
            return; 
        } else {
            if (packets_for_ip_are_buffered(sr, arp_entry->ip_addr)) { // if we are already waiting on an ARP reply for this IP
                add_packet_to_buffer(sr, p); // to maintain sequence/order of packets, we must buffer in order
            } else { // if know where we are sending already, and have no packets to this dest buffered, can just forward packet along
                memcpy(eth_hdr->ether_dhost, arp_entry->phys_addr, ETHER_ADDR_LEN);
                struct ip* ip_hdr = (struct ip*) (p + sizeof(struct sr_ethernet_hdr));
                ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
                if (ip_hdr->ip_ttl == 0) return;
                ip_hdr->ip_sum = 0;
                ip_hdr->ip_sum = checksum((uint16_t *) ip_hdr, ip_hdr->ip_hl * 2);
                //sr_printpacket(p);
                uint16_t ip_len = SWAP_UINT16(ip_hdr->ip_len);
                int len = ip_len + sizeof(struct sr_ethernet_hdr);
                // printf("*** -> sending packet of length %d\n", len);
                sr_send_packet(sr, p, len, next_hop_if->name);
            }
        }
    }
}

/*--------------------------------------------------------------------- 
 * Method: sr_handle_icmp() 
 * Scope:  Global
 *
 * This method is called when the received IP packet has protocol = ICMP
 *
 *---------------------------------------------------------------------*/
void sr_handle_icmp(struct sr_instance* sr,
                    uint8_t* p,
                    struct ip* ip_hdr,
                    struct sr_if* interface){
    // printf("*** handle icmp\n");
    uint8_t protocol = ip_hdr->ip_p;
    if (protocol != ICMP_PROTOCOL) return;
    // ptr arithmetic is in units of struct size
    struct icmp *icmp_hdr = (struct icmp *) (ip_hdr + 1);
    if (icmp_hdr->icmp_type != ICMP_ECHO_REQUEST) {
        return;
    } 

    
    uint16_t ip_len = SWAP_UINT16(ip_hdr->ip_len);
    int total_len_16 = (ip_len - (ip_hdr->ip_hl * 4)) / 2;

    // send icmp reply
    // update ICMP checksum
    icmp_hdr->icmp_type = ICMP_ECHO_REPLY;
    icmp_hdr->icmp_sum = 0;
        // note checksum expects the length in 16-bit increments
    uint16_t new_sum = checksum((uint16_t *) icmp_hdr, total_len_16);
    icmp_hdr->icmp_sum = new_sum;
    // update IP header
    struct in_addr ip_src_tmp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_src_tmp;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = checksum((uint16_t *) ip_hdr, ip_hdr->ip_hl * 2);
    // update ethernet header
    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) p;
    struct sr_if* router_if = get_router_interface(sr);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, router_if->addr, ETHER_ADDR_LEN);
    int len = ip_len + sizeof(struct sr_ethernet_hdr);
    // printf("*** -> sending packet of length %d\n", len);
    //sr_printpacket(p);
    sr_send_packet(sr, p, len, router_if->name);
}