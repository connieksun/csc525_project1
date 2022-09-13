/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_router_helper.h"
#include "sr_arp.h"
#include "sr_ip.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);
    sr_printpacket(packet);
    
    // actual packet handling begins here
    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) packet;
    uint16_t eth_type = SWAP_UINT16(eth_hdr->ether_type);
    if (eth_type == ETHERTYPE_ARP) {
        sr_handle_arp_packet(sr, packet);
    } else if (eth_type == ETHERTYPE_IP) {
        sr_handle_ip_packet(sr, packet);
    } else
        fprintf(stderr, "*** Error: ethertype %02x unknown\n", eth_type);

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method: handle_arp_packet(struct sr_ethernet_hdr* p) 
 * Scope:  Global
 *
 * This method is called when the ethernet header is ARP type
 *
 *---------------------------------------------------------------------*/
void sr_handle_arp_packet(struct sr_instance* sr, uint8_t* p){
    printf("*** handle arp packet\n");
    struct sr_arphdr* arp_hdr  = (struct sr_arphdr *) (p + sizeof(struct sr_ethernet_hdr));
    unsigned short opcode = SWAP_UINT16(arp_hdr->ar_op);
    if (opcode == ARP_REQUEST)
        sr_handle_arp_request(sr, p, arp_hdr);
    else if (opcode == ARP_REPLY)
        sr_handle_arp_reply(sr, p);
    else
        fprintf(stderr, "*** Error: sr does not handle ARP op %02x\n", opcode);
}

/*--------------------------------------------------------------------- 
 * Method: handle_ip_packet(struct_sr_ethernet_hdr* eth_hdr) 
 * Scope:  Global
 *
 * This method is called when the ethernet header is IP type
 *
 *---------------------------------------------------------------------*/
void sr_handle_ip_packet(struct sr_instance* sr, uint8_t* p){
    printf("*** handle ip packet\n");
    struct ip* ip_hdr = (struct ip*) (p + sizeof(struct sr_ethernet_hdr));
    sr_handle_ip(sr, p, ip_hdr);

    // test checksum
    // ip_hdr->ip_sum = 0;
    // uint16_t new_sum = checksum((uint16_t *) ip_hdr, ip_hdr->ip_hl * 2);
    // new_sum = SWAP_UINT16(new_sum);
	// printf("\t\tCalculated Checksum: %02x\n", new_sum);
}


/*--------------------------------------------------------------------- 
 * Method: print_packet(uint8_t* p) 
 * Scope:  Global
 *
 * This method is called for debugging purposes. Print information about
 * packet p.
 *
 *---------------------------------------------------------------------*/

void sr_printpacket(uint8_t* p) {
	sr_print_eth_hdr(p);
}

void print_hardware_address(uint8_t *addr_ptr, int len){
    for (int i = 0; i < len; i++) {
        printf("%01x", addr_ptr[i]);
        if (i != len - 1) 
            printf(":");
    }
    printf("\n");
}

void print_ip_addr(uint32_t ip_32){
    struct in_addr ip_addr_struct;
    ip_addr_struct.s_addr = ip_32; 
    printf("%s\n", inet_ntoa(ip_addr_struct)); // method to convert struct in_addr to IP string
}

void sr_print_eth_hdr(uint8_t * p) {
	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) p;
	uint16_t eth_type = eth_hdr->ether_type;
	eth_type = SWAP_UINT16(eth_type);
	// ethernet header
	printf("\tEthernet Header Destination Address: ");
    print_hardware_address(eth_hdr->ether_dhost, ETHER_ADDR_LEN);
	printf("\tEthernet Header Source Address: ");
    print_hardware_address(eth_hdr->ether_shost, ETHER_ADDR_LEN);
	printf("\tType of next protocol: %04x\n", eth_type);

	// ARP/IP
	p = p + sizeof(struct sr_ethernet_hdr);
	if (eth_type == ETHERTYPE_ARP) {
		sr_print_arp_hdr(p);
		p = p + sizeof(struct sr_arphdr);
	}
	else if (eth_type == ETHERTYPE_IP) {
		sr_print_ip_hdr(p);
		p = p + sizeof(struct  ip);
	}

}

void sr_print_arp_hdr(uint8_t * p) {
	struct sr_arphdr * arp_hdr  = (struct sr_arphdr *) p;
	unsigned short hw_addr_format = SWAP_UINT16(arp_hdr->ar_hrd);
	unsigned short pr_addr_format = SWAP_UINT16(arp_hdr->ar_pro);
	printf("\t\tARP hardware address format: %02x\n", hw_addr_format);
	printf("\t\tARP protocol address format: %02x\n", pr_addr_format);
	printf("\t\tARP hardware address length: %u\n", arp_hdr->ar_hln);
	printf("\t\tARP protocol address length: %u\n", arp_hdr->ar_pln);
	unsigned short opcode = SWAP_UINT16(arp_hdr->ar_op);
	printf("\t\tARP opcode: %02x\n", opcode);
    // ARP sender addresses
	printf("\t\tARP sender hardware address: ");
    print_hardware_address(arp_hdr->ar_sha, ETHER_ADDR_LEN);
	printf("\t\tARP sender IP address: ");
    print_ip_addr(arp_hdr->ar_sip);
    // ARP target addresses
	printf("\t\tARP target hardware address: ");
    print_hardware_address(arp_hdr->ar_tha, ETHER_ADDR_LEN);
	printf("\t\tARP target IP address: ");
    print_ip_addr(arp_hdr->ar_tip);
}

void sr_print_ip_hdr(uint8_t * p) {
	struct ip * ip_hdr = (struct ip *) p; 
	printf("\t\tIP Type of Service: %01x\n", ip_hdr->ip_tos);
	unsigned short len_of_ip_pkt = SWAP_UINT16(ip_hdr->ip_len);
	printf("\t\tIP Packet Total Length: %02x\n", len_of_ip_pkt);
	unsigned short ip_iden = SWAP_UINT16(ip_hdr->ip_id);
	printf("\t\tIP Packet ID: %02x\n", ip_iden);
	unsigned short frag_off = SWAP_UINT16(ip_hdr->ip_off);
	printf("\t\tIP Fragment Offset: %02x\n", frag_off);
	printf("\t\tIP TTL: %01x\n", ip_hdr->ip_ttl);
	printf("\t\tIP Protocol: %01x\n", ip_hdr->ip_p);
	unsigned short checksum = SWAP_UINT16(ip_hdr->ip_sum);
	printf("\t\tIP Checksum: %02x\n", checksum);
	printf("\t\tIP Source Address: %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("\t\tIP Destination Address: %s\n", inet_ntoa(ip_hdr->ip_dst));
    if (ip_hdr->ip_p == ICMP_PROTOCOL)
        sr_print_icmp_hdr(ip_hdr);
}

void sr_print_icmp_hdr(struct ip* ip_hdr){
    struct icmp *icmp_hdr = (struct icmp *) (ip_hdr + 1);
    printf("\t\t\tICMP Type: %01x\n", icmp_hdr->icmp_type);
    printf("\t\t\tICMP Code: %01x\n", icmp_hdr->icmp_code);
    unsigned short checksum = SWAP_UINT16(icmp_hdr->icmp_sum);
    printf("\t\t\tICMP Checksum: %02x\n", checksum);
    unsigned short identifier = SWAP_UINT16(icmp_hdr->icmp_id);
    printf("\t\t\tICMP Identifier: %02x\n", identifier);
    unsigned short seq_num = SWAP_UINT16(icmp_hdr->icmp_sn);
    printf("\t\t\tICMP Sequence Number: %02x\n", seq_num);
}


























