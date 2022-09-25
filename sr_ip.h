/*-----------------------------------------------------------------------------
 * File: sr_ip.h
 *---------------------------------------------------------------------------*/

#ifndef SR_IP_H
#define SR_IP_H

#ifndef ICMP_PROTOCOL
#define ICMP_PROTOCOL 1
#endif

#ifndef ICMP_ECHO_REQUEST
#define ICMP_ECHO_REQUEST 8
#endif

#ifndef ICMP_ECHO_REPLY
#define ICMP_ECHO_REPLY 0
#endif

/* -- sr_ip.c -- */
void sr_handle_ip(struct sr_instance*, uint8_t*, struct ip*);
void sr_handle_icmp(struct sr_instance*, uint8_t*, struct ip*, struct sr_if*);

// define icmp struct for easier modification of fields
struct icmp {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_sum; // checksum
    uint16_t icmp_id; // identifier
    uint16_t icmp_sn; // sequence number
} __attribute__ ((packed));

#endif /* SR_IP_H */
