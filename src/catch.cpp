#include "catch.h"

void get_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {

  static size_t cnt = 1; /* packet counter */
  const ethernet_header *ethernet;

  if (PRINT_PACKAGE_NUM) {
    printf("\nPacket number %zu:\n", cnt);
  }
  cnt++;

  ethernet = (ethernet_header *)(packet);

  if (PRINT_ETHER_ADDR) {
    printf("  Src Host MAC Address: %s\n",
           ether_ntoa((const struct ether_addr *)&ethernet->ether_shost));
    printf("  Dst Host MAC Address: %s\n",
           ether_ntoa((const struct ether_addr *)&ethernet->ether_dhost));
  }

  /***** handle ethernet *****/
  switch (ntohs(ethernet->ether_type)) {
  case ETHERTYPE_IP:
    /***** IPv4 *****/
    printf("  Ethernet Type: IPv4\n");
    handle_ipv4(packet);
    break;
  case ETHERTYPE_ARP:
    /***** ARP *****/
    printf("  Ethernet Type: ARP\n");
    handle_arp(packet);
    break;
  case ETHERTYPE_IPV6:
    /***** IPv6 *****/
    printf("  Ethernet Type: IPv6\n");
    handle_ipv6(packet);
    break;
  default:
    if (PRINT_UNKNOW_ETHER_TYPE) {
      printf("  Unknown Ethernet Type: 0x%04x\n", ntohs(ethernet->ether_type));
    }
    break;
  }

  return;
}

void handle_ipv4(const u_char *packet) {
  const ipv4_header *ipv4;
  size_t size_ip;

  ipv4 = (ipv4_header *)(packet + SIZE_ETHERNET);
  size_ip = IPv4_HL(ipv4) * 4;

  if (size_ip < 20) {
    printf("    * Invalid IP header length: %zu bytes\n", size_ip);
    return;
  }

  /* print source and destination IP addresses */
  printf("    Src Host IPv4 Address: %s\n", inet_ntoa(ipv4->ip_src));
  printf("    Dst Host IPv4 Address: %s\n", inet_ntoa(ipv4->ip_dst));

  /* determine protocol */
  switch (ipv4->ip_p) {
  case IPPROTO_TCP:
    /***** TCP *****/
    printf("    Protocol: TCP\n");
    handle_tcp(packet, size_ip, ntohs(ipv4->ip_len));
    break;
    /***** UDP *****/
  case IPPROTO_UDP:
    printf("    Protocol: UDP\n");
    handle_udp(packet, size_ip, ntohs(ipv4->ip_len));
    break;
    /***** ICMP *****/
  case IPPROTO_ICMP:
    printf("    Protocol: ICMP\n");
    handle_icmp(packet, size_ip, ntohs(ipv4->ip_len));
    break;
    /***** IGMP *****/
  case IPPROTO_IGMP:
    printf("    Protocol: IGMP\n");
    handle_igmp(packet, size_ip, ntohs(ipv4->ip_len));
    break;
    /***** IP *****/
  case IPPROTO_IP:
    printf("    Protocol: IP (Dummy protocol for TCP)\n");
    break;
    /***** Other *****/
  default:
    if (PRINT_UNKNOW_IP_PROTO) {
      printf("    Unknown Protocol: %d\n", ipv4->ip_p);
    }
    break;
  }
  return;
}

void handle_ipv6(const u_char *packet) {
  const ipv6_header *ipv6;
  size_t size_ipv6;

  ipv6 = (ipv6_header *)(packet + SIZE_ETHERNET);
  size_ipv6 = 40; // TODO

  /* print source and destination IP addresses */
  printf("    Src Host IPv6 Address: %x:%x:%x:%x:%x:%x:%x:%x\n",
         ipv6->src_addr[0], ipv6->src_addr[1], ipv6->src_addr[2],
         ipv6->src_addr[3], ipv6->src_addr[4], ipv6->src_addr[5],
         ipv6->src_addr[6], ipv6->src_addr[7]);
  printf("    Dst Host IPv6 Address: %x:%x:%x:%x:%x:%x:%x:%x\n",
         ipv6->dest_addr[0], ipv6->dest_addr[1], ipv6->dest_addr[2],
         ipv6->dest_addr[3], ipv6->dest_addr[4], ipv6->dest_addr[5],
         ipv6->dest_addr[6], ipv6->dest_addr[7]);

  /* determine protocol */
  switch (ipv6->next_header) {
  case IPPROTO_TCP:
    /***** TCP *****/
    printf("    Protocol: TCP\n");
    handle_tcp(packet, size_ipv6, ntohs(ipv6->payload_len) + size_ipv6);
    break;
    /***** UDP *****/
  case IPPROTO_UDP:
    printf("    Protocol: UDP\n");
    handle_udp(packet, size_ipv6, ntohs(ipv6->payload_len) + size_ipv6);
    break;
    /***** ICMP *****/
  case IPPROTO_ICMP:
    printf("    Protocol: ICMP\n");
    handle_icmp(packet, size_ipv6, ntohs(ipv6->payload_len) + size_ipv6);
    break;
    /***** IGMP *****/
  case IPPROTO_IGMP:
    printf("    Protocol: IGMP\n");
    handle_igmp(packet, size_ipv6, ntohs(ipv6->payload_len) + size_ipv6);
    break;
    /***** IP *****/
  case IPPROTO_IP:
    printf("    Protocol: IP (Dummy protocol for TCP)\n");
    // if (ntohs(ipv6->payload_len) != 0) {
    //   printf("Payload (%hu bytes):\n", ntohs(ipv6->payload_len));
    //   print_payload((u_char *)(packet + SIZE_ETHERNET + size_ipv6),
    //                 ntohs(ipv6->payload_len));
    // }
    break;
    /***** Other *****/
  default:
    if (PRINT_UNKNOW_IP_PROTO) {
      printf("    Unknown Protocol: %d\n", ipv6->next_header);
    }
    break;
  }

  return;
}

void handle_arp(const u_char *packet) {
  const arp_header *arp;
  // size_t size_arp;

  arp = (arp_header *)(packet + SIZE_ETHERNET);
  // size_arp = 28; // TODO

  (arp->opcode == 1) ? printf("    Opcode: ARP Request\n")
                     : printf("    Opcode: ARP Reply\n");

  /* determine protocol */
  switch (ntohs(arp->pro_type)) {
  case ETHERTYPE_IP:
    /***** IPv4 *****/
    printf("    Protocol: IPv4\n");
    /* print source and destination MAC & IP addresses */
    printf("      Src Host MAC address: %x:%x:%x:%x:%x:%x\n", arp->src_mac[0],
           arp->src_mac[1], arp->src_mac[2], arp->src_mac[3], arp->src_mac[4],
           arp->src_mac[5]);
    printf("      Src Host IPv4 Address: %d.%d.%d.%d\n", arp->src_ip[0],
           arp->src_ip[1], arp->src_ip[2], arp->src_ip[3]);
    printf("      Dst Host MAC address: %x:%x:%x:%x:%x:%x\n", arp->dest_mac[0],
           arp->dest_mac[1], arp->dest_mac[2], arp->dest_mac[3],
           arp->dest_mac[4], arp->dest_mac[5]);
    printf("      Dst Host IPv4 Address: %d.%d.%d.%d\n", arp->dest_ip[0],
           arp->dest_ip[1], arp->dest_ip[2], arp->dest_ip[3]);
    break;
    /***** Other *****/
  default:
    if (PRINT_UNKNOW_IP_PROTO) {
      printf("    Unknown Protocol: 0x%04x\n", ntohs(arp->pro_type));
    }
  }
  return;
}

void handle_tcp(const u_char *packet, size_t hdr_len, size_t total_len) {
  const tcp_header *tcp;
  const u_char *payload;
  size_t size_tcp;
  size_t size_payload;

  tcp = (tcp_header *)(packet + SIZE_ETHERNET + hdr_len);
  size_tcp = TH_OFF(tcp) * 4;

  if (size_tcp < 20) {
    printf("      * Invalid TCP header length: %zu bytes\n", size_tcp);
    return;
  }

  printf("      Src port: %d\n", ntohs(tcp->th_sport));
  printf("      Dst port: %d\n", ntohs(tcp->th_dport));

  payload = (u_char *)(packet + SIZE_ETHERNET + hdr_len + size_tcp);

  if (total_len > hdr_len + size_tcp) {
    size_payload = total_len - (hdr_len + size_tcp);
    printf("Payload (%zu bytes):\n", size_payload);
    print_payload(payload, size_payload);
  }

  return;
}

void handle_udp(const u_char *packet, size_t hdr_len, size_t total_len) {
  const udp_header *udp;
  const u_char *payload;
  size_t size_udp;
  size_t size_payload;

  udp = (udp_header *)(packet + SIZE_ETHERNET + hdr_len);
  size_udp = 8; // TODO

  printf("      Src port: %d\n", ntohs(udp->src_port));
  printf("      Dst port: %d\n", ntohs(udp->dst_port));

  payload = (u_char *)(packet + SIZE_ETHERNET + hdr_len + size_udp);

  if (total_len > hdr_len + size_udp) {
    size_payload = total_len - (hdr_len + size_udp);
    printf("Payload (%zu bytes):\n", size_payload);
    print_payload(payload, size_payload);
  }

  return;
}

void handle_icmp(const u_char *packet, size_t hdr_len, size_t total_len) {
  const u_char *payload;
  size_t size_icmp;
  size_t size_payload;

  size_icmp = 8; // TODO

  payload = (u_char *)(packet + SIZE_ETHERNET + hdr_len + size_icmp);

  if (total_len > hdr_len + size_icmp) {
    size_payload = total_len - (hdr_len + size_icmp);
    printf("Payload (%zu bytes):\n", size_payload);
    print_payload(payload, size_payload);
  }

  return;
}

void handle_igmp(const u_char *packet, size_t hdr_len, size_t total_len) {
  const u_char *payload;
  size_t size_igmp;
  size_t size_payload;

  size_igmp = 80; // TODO

  payload = (u_char *)(packet + SIZE_ETHERNET + hdr_len + size_igmp);

  if (total_len > hdr_len + size_igmp) {
    size_payload = total_len - (hdr_len + size_igmp);
    printf("Payload (%zu bytes):\n", size_payload);
    print_payload(payload, size_payload);
  }

  return;
}