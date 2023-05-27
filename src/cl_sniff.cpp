#include "sniffer.h"
#include "utils/hdr.h"
#include "utils/utils.h"
#include <pcap/pcap.h>
#include <sys/types.h>

std::vector<packet_struct *> Sniffer::pkt; // packet
bool shouldStop = false;

// Callback function for pcap_loop
Sniffer::Sniffer() {
  dev = NULL;
  allDev_ptr = NULL;
  dumper = NULL;
  status = Init;
  findAllDevs();
}

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
void Sniffer::Select_dev(const char *devName) {
    // dev = pcap_lookupdev(errbuf);
    dev = devName;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, -1, 1000, errbuf);

    // Open the device for sniffing
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }
}

// Start sniffing
void Sniffer::startSniffing() {
    status = Start;
}

// Stop sniffing
void Sniffer::stopSniffing() {
    status = Stop;
}

// Sniffing thread
void Sniffer::sniff() {
  // Open the device for sniffing
  std::string fn = "data/traffic.pcap";
  const char *fn_c = fn.c_str();
  dumpfile = pcap_dump_open(handle, fn_c);
  // pcap_dump_open(handle, fn_c);
  while (TRUE) {
    if (shouldStop || status == Stop) {
      break;
    }
    if (status == Start) {
      pcap_dispatch(handle, -1, get_packet, (unsigned char *)dumpfile);
    } else if (status == Stop) {
      //LOG("Stop");
    } else {
      //LOG("Initiating...");
    } 
  }
  sniffing_thread_stopped.set_value();
}

// Start sniffing thread
void Sniffer::stop() {
    //LOG("Stopping sniffing thread");
    shouldStop = true;
    //LOG("Waiting for sniffing thread to stop");
    if (handle != nullptr) {
        pcap_breakloop(handle);
    }
    sniffing_thread_stopped.get_future().wait();
}

// Callback function for pcap_loop
void Sniffer::get_packet(u_char *args, const struct pcap_pkthdr *header,
                         const u_char *packet) {
  pcap_dump(args, header, packet);

  // Create a new packet_struct
  packet_struct *pkt_p = new packet_struct;
  pkt_p->len = SIZE_ETHERNET;
  pkt_p->time = currentDataTime();
  pkt_p->eth_hdr = (ethernet_header *)(packet);

  // Handle different network types
  switch (ntohs(pkt_p->eth_hdr->ether_type)) {
  // IPv4
  case ETHERTYPE_IP: {
    pkt_p->net_type = IPv4;
    handle_ipv4(packet, pkt_p);
    break;
  }
  // ARP
  case ETHERTYPE_ARP:
    pkt_p->net_type = ARP;
    handle_arp(packet, pkt_p);
    break;
  // IPv6
  case ETHERTYPE_IPV6:
    pkt_p->net_type = IPv6;
    handle_ipv6(packet, pkt_p);
    break;
  default:
    pkt_p->net_type = Unet;
    break;
  }

  // If the packet is not a unknown type
  void *packet_cpy = malloc(pkt_p->len);
  memcpy(packet_cpy, packet, pkt_p->len);

  // Store the packet
  pkt_p->len = SIZE_ETHERNET;
  pkt_p->eth_hdr = (ethernet_header *)(packet_cpy);

  // Handle different network types
  switch (ntohs(pkt_p->eth_hdr->ether_type)) {
  // IPv4
  case ETHERTYPE_IP: {
    pkt_p->net_type = IPv4;
    handle_ipv4((const u_char *)packet_cpy, pkt_p);
    break;
  }
  // ARP
  case ETHERTYPE_ARP:
    pkt_p->net_type = ARP;
    handle_arp((const u_char *)packet_cpy, pkt_p);
    break;
  // IPv6
  case ETHERTYPE_IPV6:
    pkt_p->net_type = IPv6;
    handle_ipv6((const u_char *)packet_cpy, pkt_p);
    break;
  default:
    pkt_p->net_type = Unet;
    break;
  }

  free(packet_cpy);
  delete pkt_p;

  return;
}

// Handle ARP packets
void Sniffer::handle_ipv4(const u_char *packet, packet_struct *pkt_p) {
  // Get the IPv4 header
  pkt_p->net_hdr.ipv4_hdr = (ipv4_header *)(packet + SIZE_ETHERNET);
  long size_ip = IPv4_HL(pkt_p->net_hdr.ipv4_hdr) * 4;
  pkt_p->len += size_ip;

  // Get the transport layer header
  switch (pkt_p->net_hdr.ipv4_hdr->ip_p) {
  // TCP
  case IPPROTO_TCP:
    pkt_p->trs_type = TCP;
    pkt_p->trs_hdr.tcp_hdr = (tcp_header *)(packet + pkt_p->len);
    break;
  // UDP
  case IPPROTO_UDP:
    pkt_p->trs_type = UDP;
    pkt_p->trs_hdr.udp_hdr = (udp_header *)(packet + pkt_p->len);
    break;
  // ICMP
  case IPPROTO_ICMP:
    pkt_p->trs_type = ICMP;
    pkt_p->trs_hdr.icmp_hdr = (icmp_header *)(packet + pkt_p->len);
    break;
  // IGMP
  case IPPROTO_IGMP:
    pkt_p->trs_type = IGMP;
    pkt_p->trs_hdr.igmp_hdr = (igmp_header *)(packet + pkt_p->len);
    break;
  default:
    pkt_p->trs_type = Utrs;
    break;
  }

  // sub size_ip, because ip_len include it
  pkt_p->len -= size_ip; 

  // TODO: Check if it is necessary
  pkt_p->len += ntohs(pkt_p->net_hdr.ipv4_hdr->ip_len); 
  return;
}

// Handle ARP packets
void Sniffer::handle_ipv6(const u_char *packet, packet_struct *pkt_p) {
  // Get the IPv6 header
  pkt_p->net_hdr.ipv6_hdr = (ipv6_header *)(packet + SIZE_ETHERNET);
  pkt_p->len += SIZE_IPv6;

  // Get the transport layer header
  switch (pkt_p->net_hdr.ipv6_hdr->next_header) { 
  // TCP
  case IPPROTO_TCP:
    pkt_p->trs_type = TCP;
    pkt_p->trs_hdr.tcp_hdr = (tcp_header *)(packet + pkt_p->len);
    break;
  // UDP
  case IPPROTO_UDP:
    pkt_p->trs_type = UDP;
    pkt_p->trs_hdr.udp_hdr = (udp_header *)(packet + pkt_p->len);
    break;
  // ICMP
  case IPPROTO_ICMP:
    pkt_p->trs_type = ICMP;
    pkt_p->trs_hdr.icmp_hdr = (icmp_header *)(packet + pkt_p->len);
    break;
  // IGMP
  case IPPROTO_IGMP:
    pkt_p->trs_type = IGMP;
    pkt_p->trs_hdr.igmp_hdr = (igmp_header *)(packet + pkt_p->len);
    break;
  default:
    pkt_p->trs_type = Utrs;
    break;
  }
  // TODO: Check if it is necessary
  pkt_p->len += ntohs(pkt_p->net_hdr.ipv6_hdr->payload_len); 
  return;
}

// Handle ARP packets
void Sniffer::handle_arp(const u_char *packet, packet_struct *pkt_p) {
  pkt_p->net_hdr.arp_hdr = (arp_header *)(packet + SIZE_ETHERNET);
  pkt_p->len += SIZE_ARP;
  return;
}