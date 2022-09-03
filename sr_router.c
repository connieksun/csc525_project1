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

}/* end sr_ForwardPacket */


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


void sr_print_eth_hdr(uint8_t * p) {
	struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) p;
	uint8_t * dest_host_addr = eth_hdr->ether_dhost;
	uint8_t * src_host_addr = eth_hdr->ether_shost;
	uint16_t eth_type = eth_hdr->ether_type;
	eth_type = SWAP_UINT16(eth_type);
	// ethernet header
	printf("Ethernet Header Destination Address: %02x%02x.%02x%02x.%02x%02x\n", \
			dest_host_addr[0], dest_host_addr[1], dest_host_addr[2], dest_host_addr[3], \
			dest_host_addr[4], dest_host_addr[5]);
	printf("Ethernet Header Source Address: %02x%02x.%02x%02x.%02x%02x\n", \
			src_host_addr[0], src_host_addr[1], src_host_addr[2], src_host_addr[3], \
			src_host_addr[4], src_host_addr[5]);

	printf("Type of next protocol: %04x\n", eth_type);

	// ARP/IP
	p = p + sizeof(struct sr_ethernet_hdr);
	if (eth_type == ETHERTYPE_ARP) {
		sr_print_arp_hdr(p);
		p = p + sizeof(struct sr_arphdr);
	}
	else if (eth_type == ETHERTYPE_IP) {
		//sr_print_ip_hdr(p);
		p = p + sizeof(struct  ip);
	}

}


void sr_print_arp_hdr(uint8_t * p) {
	struct sr_arphdr * arp_hdr  = (struct sr_arphdr *) p;
	unsigned short hw_addr_format = SWAP_UINT16(arp_hdr->ar_hrd);
	unsigned short pr_addr_format = SWAP_UINT16(arp_hdr->ar_pro);
	printf("ARP hardware address format: %02x\n", hw_addr_format);
	printf("ARP protocal address format: %02x\n", pr_addr_format);
	printf("ARP hardware address length: %u\n", arp_hdr->ar_hln);
	printf("ARP protocal address length: %u\n", arp_hdr->ar_pln);
	unsigned short opcode = SWAP_UINT16(arp_hdr->ar_op);
	printf("ARP opcode: %02x\n", opcode);
	printf("ARP sender hardware address: ");
	for (int i = 0; i < ETHER_ADDR_LEN;  i++) {
		printf("%01x", arp_hdr->ar_sha[i]);
		if (i != ETHER_ADDR_LEN - 1 && i % 2 == 1) {
			printf(".");
		}
	}
	printf("\n");
	printf("ARP sender IP address: ");
	uint8_t sender_ipv4[IPV4_ADDR_LEN];
	convert_uint32_to_ip(arp_hdr->ar_sip, sender_ipv4);
	for (int i = 0; i < IPV4_ADDR_LEN; i++) {
		printf("%01x", sender_ipv4[i]);
		if (i != IPV4_ADDR_LEN - 1) {
			printf(".");
		}
	}
	printf("\n");
	printf("ARP target hardware address: ");
	for (int i = 0; i < ETHER_ADDR_LEN; i++) {
		printf("%01x", arp_hdr->ar_tha[i]);
		if (i != ETHER_ADDR_LEN - 1) {
			printf(".");
		}
	}
	printf("\n");
	printf("ARP target IP address: ");
	uint8_t target_ipv4[IPV4_ADDR_LEN];
	convert_uint32_to_ip(arp_hdr->ar_tip, target_ipv4);
	for (int i = 0; i < IPV4_ADDR_LEN; i++) {
		printf("%01x", target_ipv4[i]);
		if (i != IPV4_ADDR_LEN - 1) {
			printf(".");
		}
	}
	printf("\n");

}


























