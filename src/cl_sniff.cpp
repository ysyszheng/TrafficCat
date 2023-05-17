#include "sniffer.h"
#include "utils/hdr.h"
#include "utils/utils.h"
#include <pcap/pcap.h>
#include <sys/types.h>

std::vector<packet_struct *> Sniffer::pkt; // packet
bool shouldStop = false;

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

bool Sniffer::findAllDevs() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_findalldevs(&allDev_ptr, errbuf);

  if (allDev_ptr == NULL) {
    ERROR_INFO(errbuf);
    exit(1);
  }

  if (PRINT_DEV_NAME) {
    printf("Available devices: \n");
  }

  for (pcap_if_t *pdev = allDev_ptr; pdev; pdev = pdev->next) {
    if (PRINT_DEV_NAME) {
      std::cout << "  @: " << pdev->name << std::endl;
    }
    allDev_vec.push_back(pdev);
  }
  return TRUE;
}

void Sniffer::Select_dev(const char *devName) {
    dev = devName;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, -1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(2);
    }
}

void Sniffer::startSniffing() {
    status = Start;
}

void Sniffer::stopSniffing() {
    status = Stop;
}

void Sniffer::sniff() {
  std::string fn = "../data/" + currentDataTime() + ".pcap";
  const char *fn_c = fn.c_str();
  dumpfile = pcap_dump_open(handle, fn_c);
  while (TRUE) {
    if (shouldStop) {
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

void Sniffer::stop() {
    shouldStop = true;
    if (handle != nullptr) {
        pcap_breakloop(handle);
    }
    sniffing_thread_stopped.get_future().wait();
}

void Sniffer::get_packet(u_char *args, const struct pcap_pkthdr *header,
                         const u_char *packet) {
  pcap_dump(args, header, packet);
  static size_t cnt = 0;

  packet_struct *pkt_p = new packet_struct;
  pkt_p->len = SIZE_ETHERNET;
  pkt_p->time = currentDataTime();
  pkt_p->eth_hdr = (ethernet_header *)(packet);

  switch (ntohs(pkt_p->eth_hdr->ether_type)) {
  case ETHERTYPE_IP: {
    pkt_p->net_type = IPv4;
    handle_ipv4(packet, pkt_p);
    break;
  }
  case ETHERTYPE_ARP:
    pkt_p->net_type = ARP;
    handle_arp(packet, pkt_p);
    break;
  case ETHERTYPE_IPV6:
    pkt_p->net_type = IPv6;
    handle_ipv6(packet, pkt_p);
    break;
  default:
    pkt_p->net_type = Unet;
    break;
  }

  void *packet_cpy = malloc(pkt_p->len);
  memcpy(packet_cpy, packet, pkt_p->len);

  pkt_p->len = SIZE_ETHERNET;
  pkt_p->eth_hdr = (ethernet_header *)(packet_cpy);

  switch (ntohs(pkt_p->eth_hdr->ether_type)) {
  case ETHERTYPE_IP: {
    pkt_p->net_type = IPv4;
    handle_ipv4((const u_char *)packet_cpy, pkt_p);
    break;
  }
  case ETHERTYPE_ARP:
    pkt_p->net_type = ARP;
    handle_arp((const u_char *)packet_cpy, pkt_p);
    break;
  case ETHERTYPE_IPV6:
    pkt_p->net_type = IPv6;
    handle_ipv6((const u_char *)packet_cpy, pkt_p);
    break;
  default:
    pkt_p->net_type = Unet;
    break;
  }

  if (pkt_p->net_type != Unet) { // Known types
    cnt++;
    pkt_p->no = cnt;

    Sniffer::pkt.push_back(pkt_p);
  }
  return;
}

void Sniffer::handle_ipv4(const u_char *packet, packet_struct *pkt_p) {
  pkt_p->net_hdr.ipv4_hdr = (ipv4_header *)(packet + SIZE_ETHERNET);
  long size_ip = IPv4_HL(pkt_p->net_hdr.ipv4_hdr) * 4;
  pkt_p->len += size_ip;

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
  pkt_p->len += ntohs(pkt_p->net_hdr.ipv4_hdr->ip_len); // TODO

  return;
}

void Sniffer::handle_ipv6(const u_char *packet, packet_struct *pkt_p) {
  pkt_p->net_hdr.ipv6_hdr = (ipv6_header *)(packet + SIZE_ETHERNET);
  pkt_p->len += SIZE_IPv6;

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

void Sniffer::handle_arp(const u_char *packet, packet_struct *pkt_p) {
  pkt_p->net_hdr.arp_hdr = (arp_header *)(packet + SIZE_ETHERNET);
  pkt_p->len += SIZE_ARP;
  return;
}

int main() {
    Sniffer sniffer;
    bool getdev = sniffer.findAllDevs();
    if (!getdev) {
        LOG("No device found!");
        return 0;
    }
    char name[100];
    printf("Enter the device you select: ");
    scanf("%s", name);  // 读取字符串
    sniffer.Select_dev(name);

    // Start a new thread for sniffing
    std::thread snifferThread([&sniffer]() { sniffer.sniff(); });

    // Command loop
    std::string command;
    while (true) {
        std::cout << "Enter your command (start/stop/exit): ";
        std::cin >> command;
        if (command == "start") {
            sniffer.startSniffing();
        } else if (command == "stop") {
            sniffer.stopSniffing();
        } else if (command == "exit") {
            sniffer.stop();
            break;
        } else {
            std::cout << "Unknown command: " << command << "\n";
        }
    }

    // Join the sniffing thread
    if (snifferThread.joinable()) {
        snifferThread.join();
    }

    return 0;
}
