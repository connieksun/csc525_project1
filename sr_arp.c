/**********************************************************************
 * file:  sr_arp.c 
 *
 * Description:
 * 
 * This file contains all the functions to handle ARP
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_router_helper.h"
#include "sr_arp.h"


/*--------------------------------------------------------------------- 
 * Method: handle_arp_request(struct sr_arphdr* p) 
 * Scope:  Global
 *
 * This method is called when the received ARP packet has opcode = request
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp_request(struct sr_instance* sr,
                            uint8_t* p,
                            struct sr_arphdr* arphdr){
    printf("*** handle arp request\n");
    print_if_ip(sr);
    struct sr_if *interface = sr->if_list;
    while (interface){
        if (interface->ip == arphdr->ar_tip) {
            sr_send_arp_reply(sr, p, interface);
            break;
        }
        interface = interface->next;
    }
}

void sr_send_arp_reply(struct sr_instance* sr,
                        uint8_t* p,
                     
                        struct sr_if* interface){
    printf("*** send arp reply\n");
    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) p;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);

    struct sr_arphdr* arp_hdr = (struct sr_arphdr *) (p + sizeof(struct sr_ethernet_hdr));
    arp_hdr->ar_op = SWAP_UINT16(ARP_REPLY);
    memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = arp_hdr->ar_sip;
    memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = interface->ip;

    unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    printf("*** -> sending packet of length %d\n", len);
    sr_printpacket(p);
    sr_send_packet(sr, p, len, interface->name);
}

/*--------------------------------------------------------------------- 
 * Method: handle_arp_packet(struct sr_arphdr* p) 
 * Scope:  Global
 *
 * This method is called when the received ARP packet has opcode = reply
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp_reply(struct sr_instance* sr,
                         uint8_t* p){
    printf("*** handle arp reply\n");
    // TODO
}

void sr_send_arp_request(struct sr_instance* sr, uint8_t* p, struct ip* ip_hdr) {
    printf("*** send arp request\n");
    uint8_t* packet_to_send = malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) packet_to_send;
    struct sr_arphdr* arp_hdr = (struct sr_arphdr*) packet_to_send + sizeof(struct sr_ethernet_hdr);
    struct sr_ethernet_hdr * eth_hdr_of_packet_to_fwd = (struct sr_ethernet_hdr *) p;
    eth_hdr->ether_type = ETHERTYPE_ARP;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        eth_hdr->ether_dhost[i] = 0xFF; // broadcast to all dest
        eth_hdr->ether_shost[i] = eth_hdr_of_packet_to_fwd->ether_dhost[i]; // set source to be me, who was the recipient of the packet we need to fwd
    }
    // end filling ethernet header
    // begin filling arp header
    arp_hdr->ar_hrd = SWAP_UINT16(ARPHDR_ETHER);
    arp_hdr->ar_pro = SWAP_UINT16(ETHERTYPE_IP);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = IPV4_ADDR_LEN;
    arp_hdr->ar_op = SWAP_UINT16(ARP_REQUEST);
    memcpy(arp_hdr->ar_sha, eth_hdr->ether_shost, ETHER_ADDR_LEN);
    struct sr_if* router_if = get_router_interface(sr);
    arp_hdr->ar_sip = router_if->ip;
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        arp_hdr->ar_tha[i] = 0x00; 
    }
    arp_hdr->ar_tip = ip_hdr->ip_dst.s_addr;
    sr_print_eth_hdr((uint8_t*)eth_hdr);
    sr_print_arp_hdr((uint8_t*)arp_hdr);
}

// prints routing table's destination IPs
// not sure why i put it here
void print_rt_ip(struct sr_instance *sr){
    struct sr_rt *rt = sr->routing_table;
    char *ip_addr;
    while (rt){
        ip_addr = inet_ntoa(rt->dest); // method to convert struct in_addr to IP string
        printf("rt IP: %s\n", ip_addr);
        rt = rt->next;
    }
}

// prints router's interface IPs
// not sure why i put it here
void print_if_ip(struct sr_instance *sr){
    struct sr_if *interface = sr->if_list;
    char *ip_addr;
    struct in_addr ip_addr_struct;
    while (interface){
        ip_addr_struct.s_addr = interface->ip;
        ip_addr = inet_ntoa(ip_addr_struct); // method to convert struct in_addr to IP string
        printf("rt IP: %s\n", ip_addr);
        interface = interface->next;
    }
}