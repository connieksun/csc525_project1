/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * 90904102 
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_router_helper.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define SWAP_UINT16(x) (((x) >> 8) |((x) << 8))
#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))


/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_packet_buffer
 *
 * If waiting on an ARP reply, must buffer packets. This struct forms a LL
 *  to do so.
 *
 * -------------------------------------------------------------------------- */
struct sr_packet_buffer {
    uint8_t * packet;
    struct sr_packet_buffer* prev;
    struct sr_packet_buffer* next;
};

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arp_cache* arp_cache;
    struct sr_packet_buffer* packet_buffer;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void sr_handle_arp_packet(struct sr_instance*, uint8_t *);
void sr_handle_ip_packet(struct sr_instance*, uint8_t *);
void sr_printpacket(uint8_t *packet);
void sr_print_eth_hdr(uint8_t *p);
void sr_print_arp_hdr(uint8_t *p);
void sr_print_ip_hdr(uint8_t *p);
void sr_print_icmp_hdr(struct ip*);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );


/* -- sr_router_helper.c -- */
uint16_t checksum(uint16_t *buf, int len);
struct sr_arp_cache* get_cached_arp_entry(struct sr_instance* sr, uint8_t * p, struct in_addr dst);
struct sr_if* get_router_interface(struct sr_instance*);
struct sr_if* get_best_if_match(struct sr_instance*, struct in_addr);
struct sr_rt* get_best_rt_match(struct sr_instance*, struct in_addr);
void add_packet_to_buffer(struct sr_instance*, uint8_t*);
void handle_buffered_packets(struct sr_instance*, uint32_t);
int packets_for_ip_are_buffered(struct sr_instance*, uint32_t);

#endif /* SR_ROUTER_H */
