/**********************************************************************
 * file:  sr_ip.c 
 *
 * Description:
 * 
 * This file contains all the functions to handle IP forwarding (and ICMP)
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
 *
 *---------------------------------------------------------------------*/
void sr_handle_ip(struct sr_instance* sr,
                            uint8_t* p,
                            struct ip* ip_hdr){
    printf("*** handle ip\n");
    struct in_addr dst = ip_hdr->ip_dst;
    struct sr_if* interface_match = get_interface_dst(sr, dst);
    if (interface_match) {
        sr_handle_icmp(sr, p, ip_hdr, interface_match);
    } else {
        // decrement TTL
        // forwarding
        printf("destination is not router\n");
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
    printf("*** handle icmp\n");
    uint8_t protocol = ip_hdr->ip_p;
    if (protocol != ICMP_PROTOCOL) return;
    // ptr arithmetic is in units of struct size
    struct icmp *icmp_hdr = (struct icmp *) (ip_hdr + 1);
    if (icmp_hdr->icmp_type != ICMP_ECHO_REQUEST) return;

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
    uint8_t *tmp = eth_hdr->ether_dhost;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    int len = ip_len + sizeof(struct sr_ethernet_hdr);
    printf("*** -> sending packet of length %d\n", len);
    sr_printpacket(p);
    sr_send_packet(sr, p, len, interface->name);
}