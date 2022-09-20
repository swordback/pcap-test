#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <string.h>

struct ethernet_hdr
{
    u_int8_t ether_dhost[6]; // destination host
    u_int8_t ether_shost[6]; // source host
    u_int16_t ether_type; // type of ethernet
};

struct ipv4_hdr
{
    u_int8_t ver_ihl; //version and IHL
    u_int8_t DSCP_ECN; //DSCP and ECN
    u_int16_t len; // total length
    u_int16_t id; // identification
    u_int16_t flag_frag_offset; // flags and fragment offset
    u_int8_t ttl; // time to live
    u_int8_t protocol; // protocol
    u_int16_t checksum; // header checksum
    uint32_t ip_shost; // source IP address
    uint32_t ip_dhost; // dest IP address
};

struct TCP_hdr
{
    u_int16_t tcp_sport; // source port
    u_int16_t tcp_dport; // dest port
    uint32_t seq_num; // sequence number
    uint32_t ack_num; // acknowledge number
    u_int16_t data_offset_else; // data offset and else things
    u_int16_t window_size; // window size
    u_int16_t checksum; // checksum
    u_int16_t urg_pointer; // urgent pointer
};

#endif