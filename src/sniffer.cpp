#include "sniffer.h"
#include "utils/hdr.h"
#include "utils/utils.h"
#include <pcap/pcap.h>
#include <sys/types.h>
#include <cstdlib>

std::vector<packet_struct *> Sniffer::pkt; // packet
View *Sniffer::view;                       // view

// Callback function for pcap_loop
Sniffer::Sniffer() {
  dev = NULL;
  allDev_ptr = NULL;
  dumper = NULL;
  status = Init;
  findAllDevs();
}

// Find all available devices
Sniffer::~Sniffer() {
  pcap_dump_close(dumpfile);
  if (allDev_ptr)
    pcap_freealldevs(allDev_ptr);
  if (handle)
    pcap_close(handle);
}

// Find all available devices
bool Sniffer::findAllDevs() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_findalldevs(&allDev_ptr, errbuf);

  // pcap_if_t *allDev_ptr;
  if (allDev_ptr == NULL) {
    ERROR_INFO(errbuf);
    exit(1);
  }

  // Print all available devices
  if (PRINT_DEV_NAME) {
    printf("Available devices: \n");
  }

  // Store all available devices in a vector
  for (pcap_if_t *pdev = allDev_ptr; pdev; pdev = pdev->next) {
    if (PRINT_DEV_NAME) {
      std::cout << "  @: " << pdev->name << std::endl;
    }
    allDev_vec.push_back(pdev);
  }
  return TRUE;
}

// Select a device to sniff
void Sniffer::getDevName(const char *devName) { dev = devName; }

// Open device for sniffing
bool Sniffer::getDevInfo() {
  char errbuf[PCAP_ERRBUF_SIZE];
 
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    ERROR_INFO(errbuf);
    net = 0;
    mask = 0;
    return FALSE;
  }
  // Open device for sniffing
  if (PRINT_DEV_INFO) {
    printf("Device Info:\n");
    printf("NET: %d.%d.%d.%d\tmask: %d.%d.%d.%d\n", (net >> 24) & 0xff,
           (net >> 16) & 0xff, (net >> 8) & 0xff, (net)&0xff,
           (mask >> 24) & 0xff, (mask >> 16) & 0xff, (mask >> 8) & 0xff,
           mask & 0xff);
  }
  return TRUE;
}


void Sniffer::getView(View *viewObj) { view = viewObj; }

// Start sniffing
void Sniffer::sniff() {
  fn = "../data/" + currentDataTime();
  std::string fn_pcap = fn + ".pcap";
  const char *fn_c = fn_pcap.c_str();
  dumpfile = pcap_dump_open(handle, fn_c);
  // pcap_dump_open(handle, fn_c);
  while (TRUE) {
    if (status == Start) {
      pcap_dispatch(handle, -1, get_packet, (unsigned char *)dumpfile);
    } else if (status == Stop) {
      LOG("Stop");
    } else {
      LOG("Initiating...");
    }
  }
}

// Callback function for pcap_loop
void Sniffer::get_packet(u_char *args, const struct pcap_pkthdr *header,
                         const u_char *packet) {
  pcap_dump(args, header, packet);
  static size_t cnt = 0;

  // Create a new packet
  packet_struct *pkt_p = new packet_struct;
  pkt_p->len = SIZE_ETHERNET;
  pkt_p->time = currentDataTime();
  pkt_p->eth_hdr = (ethernet_header *)(packet);
  
  // Get the type of the network layer
  switch (ntohs(pkt_p->eth_hdr->ether_type)) {
  case ETHERTYPE_IP: {
    pkt_p->net_type = IPv4;
    handle_ipv4(packet, pkt_p);
    break;
  }

  // case ETHERTYPE_IPV6:
  case ETHERTYPE_ARP:
    pkt_p->net_type = ARP;
    handle_arp(packet, pkt_p);
    break;

  // case ETHERTYPE_IPV6:
  case ETHERTYPE_IPV6:
    pkt_p->net_type = IPv6;
    handle_ipv6(packet, pkt_p);
    break;
  default:
    pkt_p->net_type = Unet;
    break;
  }

  // Handle the packet
  void *packet_cpy = malloc(pkt_p->len);
  memcpy(packet_cpy, packet, pkt_p->len);
  
  // Add the packet to the vector
  pkt_p->len = SIZE_ETHERNET;
  pkt_p->eth_hdr = (ethernet_header *)(packet_cpy);

  // Get the type of the network layer
  switch (ntohs(pkt_p->eth_hdr->ether_type)) {
  // case ETHERTYPE_IP: {
  case ETHERTYPE_IP: {
    pkt_p->net_type = IPv4;
    handle_ipv4((const u_char *)packet_cpy, pkt_p);
    break;
  }
  // case ETHERTYPE_ARP:
  case ETHERTYPE_ARP:
    pkt_p->net_type = ARP;
    handle_arp((const u_char *)packet_cpy, pkt_p);
    break;
  // case ETHERTYPE_IPV6:
  case ETHERTYPE_IPV6:
    pkt_p->net_type = IPv6;
    handle_ipv6((const u_char *)packet_cpy, pkt_p);
    break;
  default:
    pkt_p->net_type = Unet;
    break;
  }

  // Handle the packet
  if (pkt_p->net_type != Unet) { // Known types
    cnt++;
    pkt_p->no = cnt;

    Sniffer::pkt.push_back(pkt_p);
    view->add_pkt(pkt_p);

  }

  free(packet_cpy);
  delete pkt_p;
  return;
}

// Handle ipv4 packet
void Sniffer::handle_ipv4(const u_char *packet, packet_struct *pkt_p) {
  pkt_p->net_hdr.ipv4_hdr = (ipv4_header *)(packet + SIZE_ETHERNET);
  long size_ip = IPv4_HL(pkt_p->net_hdr.ipv4_hdr) * 4;
  pkt_p->len += size_ip;

  // Get the type of the transport layer
  switch (pkt_p->net_hdr.ipv4_hdr->ip_p) {
  case IPPROTO_TCP:
    pkt_p->trs_type = TCP;
    pkt_p->trs_hdr.tcp_hdr = (tcp_header *)(packet + pkt_p->len);
    break;
  case IPPROTO_UDP:
    pkt_p->trs_type = UDP;
    pkt_p->trs_hdr.udp_hdr = (udp_header *)(packet + pkt_p->len);
    break;
  case IPPROTO_ICMP:
    pkt_p->trs_type = ICMP;
    pkt_p->trs_hdr.icmp_hdr = (icmp_header *)(packet + pkt_p->len);
    break;
  case IPPROTO_IGMP:
    pkt_p->trs_type = IGMP;
    pkt_p->trs_hdr.igmp_hdr = (igmp_header *)(packet + pkt_p->len);
    break;
  default:
    pkt_p->trs_type = Utrs;
    break;
  }

  pkt_p->len -= size_ip; // sub size_ip, because ip_len include it
  pkt_p->len += ntohs(pkt_p->net_hdr.ipv4_hdr->ip_len); 

  return;
}

// Handle ipv6 packet
void Sniffer::handle_ipv6(const u_char *packet, packet_struct *pkt_p) {
  pkt_p->net_hdr.ipv6_hdr = (ipv6_header *)(packet + SIZE_ETHERNET);
  pkt_p->len += SIZE_IPv6;
  // Get the type of the transport layer
  switch (pkt_p->net_hdr.ipv6_hdr->next_header) { // TODO
  case IPPROTO_TCP:
    pkt_p->trs_type = TCP;
    pkt_p->trs_hdr.tcp_hdr = (tcp_header *)(packet + pkt_p->len);
    break;
  case IPPROTO_UDP:
    pkt_p->trs_type = UDP;
    pkt_p->trs_hdr.udp_hdr = (udp_header *)(packet + pkt_p->len);
    break;
  case IPPROTO_ICMP:
    pkt_p->trs_type = ICMP;
    pkt_p->trs_hdr.icmp_hdr = (icmp_header *)(packet + pkt_p->len);
    break;
  case IPPROTO_IGMP:
    pkt_p->trs_type = IGMP;
    pkt_p->trs_hdr.igmp_hdr = (igmp_header *)(packet + pkt_p->len);
    break;
  default:
    pkt_p->trs_type = Utrs;
    break;
  }

  pkt_p->len += ntohs(pkt_p->net_hdr.ipv6_hdr->payload_len); // TODO

  return;
}

// Handle arp packet
void Sniffer::handle_arp(const u_char *packet, packet_struct *pkt_p) {
  pkt_p->net_hdr.arp_hdr = (arp_header *)(packet + SIZE_ETHERNET);
  pkt_p->len += SIZE_ARP;
  return;
}
