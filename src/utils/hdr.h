#ifndef HDR_H
#define HDR_H

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

#define SIZE_ETHERNET 14
#define SIZE_ARP 28
#define SIZE_IPv6 40
#define SIZE_ICMP 8
#define SIZE_IGMP 64 // TODO

#define ETHER_ADDR_LEN 6

/* Ethernet header */
typedef struct {
  uint8_t ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  uint8_t ether_shost[ETHER_ADDR_LEN]; /* source host address */
  uint16_t ether_type;                 /* IP? ARP? RARP? etc */
} ethernet_header;                     /* 14 bytes in total */

/* IPv4 header */
typedef struct {
  uint8_t ip_vhl;                /* version << 4 | header length >> 2 */
  uint8_t ip_tos;                /* type of service */
  uint16_t ip_len;               /* total length */
  uint16_t ip_id;                /* identification */
  u_short ip_off;                /* fragment offset field */
#define IP_RF 0x8000             /* reserved fragment flag */
#define IP_DF 0x4000             /* don't fragment flag */
#define IP_MF 0x2000             /* more fragments flag */
#define IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  uint8_t ip_ttl;                /* time to live */
  uint8_t ip_p;                  /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
} ipv4_header;
#define IPv4_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IPv4_V(ip) (((ip)->ip_vhl) >> 4)

/* ARP header */
typedef struct {
  uint16_t hard_type;  /* hardware type, 2 bytes */
  uint16_t pro_type;   /* protocal type, 2 bytes */
  u_char hard_adr_len; /* hardware address len, 1 byte */
  u_char pro_adr_len;  /* protocal address len, 1 byte */
  u_short opcode;    /* operation type, 2 bytes,1 for request, 2 for response */
  u_char src_mac[6]; /* MAC for source, 6 bytes */
  u_char src_ip[4];  /* IP for source, 4 bytes */
  u_char dest_mac[6]; /* MAC for dest, 6 bytes */
  u_char dest_ip[4];  /* IP for dest, 4 bytes */
} arp_header;

/* IPv6 header */
typedef struct {
  // u_int version : 4;    /* version, 4 bits */
  // uint8_t flow_type;    /* flow type, 1 byte */
  // u_int flow_id : 20;   /* flow id, 20 bits*/
  uint8_t vtc;
  uint8_t tcf;
  u_short flow;
  u_short payload_len;  /* length of load， 2 bytes*/
  uint8_t next_header;  /* next head，1 byte */
  uint8_t hop_limit;    /* hop limit，1 byte */
  u_short src_addr[8];  /* source address，16 bytes */
  u_short dest_addr[8]; /* dest address，16 bytes */
} ipv6_header;

/* TCP header */
typedef u_int tcp_seq;

typedef struct {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
  u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
} tcp_header;

/* UDP header */
typedef struct {
  u_short src_port;  /* source port, 2 bytes */
  u_short dst_port;  /* dest port, 2 bytes */
  u_short length;    /* length of data packet，2 bytes */
  u_short check_sum; /* check sum, 2 bytes */
} udp_header;

/* ICMP header */
typedef struct {
  u_char type;            /* type, 1 byte */
  u_char code;            /* code, 1 byte */
  u_short check_sum;      /* check sum, 2 bytes */
  uint32_t rst_of_header; /* Rest of header, 4 bytes */
} icmp_header;

/* IGMP header */
typedef struct {
  uint8_t type;
  uint8_t resp_time;
  uint16_t checksum;
  uint8_t group_addr[4];
} igmp_header;

/* data_packet */
typedef enum { Unet, ARP, IPv4, IPv6 } net_t;
typedef enum { Utrs, ICMP, IGMP, UDP, TCP } trs_t;

typedef struct {
  size_t no;
  std::string time; /* time */
  long len;         /* length */
  net_t net_type;
  trs_t trs_type;
  ethernet_header *eth_hdr; /* Ethernet header */
  union {
    arp_header *arp_hdr;   /* ARP header */
    ipv4_header *ipv4_hdr; /* IPv4 header */
    ipv6_header *ipv6_hdr; /* IPv6 header */
  } net_hdr;
  union {
    icmp_header *icmp_hdr; /* ICMP header */
    igmp_header *igmp_hdr; /* IGMP header */
    udp_header *udp_hdr;   /* UDP header */
    tcp_header *tcp_hdr;   /* TCP header */
  } trs_hdr;
} packet_struct;

#endif // HDR_H