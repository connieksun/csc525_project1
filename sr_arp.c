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
    struct sr_arphdr* arp_hdr = (struct sr_arphdr*) (p + sizeof(struct sr_ethernet_hdr));
    struct sr_arp_cache* cache_entry = malloc(sizeof(struct sr_arp_cache));
    memcpy(cache_entry->phys_addr, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    cache_entry->ip_addr = arp_hdr->ar_sip;
    struct timeval * cur_time = malloc(sizeof(struct timeval));
    gettimeofday(cur_time, NULL);
    cache_entry->time_added = cur_time->tv_sec;
    add_entry_to_cache(sr, cache_entry);
    free(cur_time);
    // TODO: is this where we want to flip 'isWaiting' back??
}

void sr_send_arp_request(struct sr_instance* sr, uint8_t* p, struct ip* ip_hdr) {
    printf("*** send arp request\n");
    int len_of_packet = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
    uint8_t* packet_to_send = malloc(len_of_packet);
    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) packet_to_send;
    struct sr_arphdr* arp_hdr = (struct sr_arphdr*) (packet_to_send + sizeof(struct sr_ethernet_hdr));
    eth_hdr->ether_type = SWAP_UINT16(ETHERTYPE_ARP);
    struct sr_if* interface = get_best_if_match(sr, ip_hdr->ip_dst);
    printf("Sending ARP packet to: %s\n", interface->name);
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        eth_hdr->ether_dhost[i] = 0xFF; // broadcast to all dest
        eth_hdr->ether_shost[i] = interface->addr[i]; // set source to be outgoing if
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
    sr_print_eth_hdr(packet_to_send);
    sr_send_packet(sr, packet_to_send, len_of_packet, interface->name);
    
}

void add_entry_to_cache(struct sr_instance* sr, struct sr_arp_cache* cache_entry) {
    struct sr_arp_cache * cache = sr->arp_cache;
    struct sr_arp_cache * last_entry = NULL;
    while (cache) {
        if (cache->ip_addr == cache_entry->ip_addr) { // if this ip already has an entry
            memcpy(cache->phys_addr, cache_entry->phys_addr, ETHER_ADDR_LEN); // just update it
            cache->time_added = cache_entry->time_added;
            free(cache_entry);
            return;
        }
        last_entry = cache; // keep track of current last entry
        cache = cache->next;
    }
    // at this point we know that the ip for which we received the hardware
    // address is not already in the cache, so we add it at the end
    if (last_entry) { // if cache had even one entry, this will be true
        last_entry->next = cache_entry;
        cache_entry->prev = last_entry;
        cache_entry->next = NULL;
    } else {
        sr->arp_cache = cache_entry;
    }
 
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