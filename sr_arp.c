/**********************************************************************
 * file:  sr_arp.c 
 *
 * Description:
 * 
 * This file contains all the functions to handle ARP
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
    //print_if_ip(sr);
    struct sr_if *interface = sr->if_list;
    while (interface){
        if (interface->ip == arphdr->ar_tip) {
            sr_send_arp_reply(sr, p, arphdr, interface);
            break;
        }
        interface = interface->next;
    }
}

void sr_send_arp_reply(struct sr_instance* sr,
                        uint8_t* p,
                        struct sr_arphdr* arphdr, 
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

void sr_send_arp_request(){
    printf("*** send arp request\n");
    // TODO
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