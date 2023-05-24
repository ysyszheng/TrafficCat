#ifndef SNIFFER_H
#define SNIFFER_H

#include "catch.h"
#include "utils/hdr.h"
#include "utils/utils.h"
#include "view.h"
#include <pcap/pcap.h>

// Sniffer
class Sniffer : public QObject {
  Q_OBJECT

  friend class MainWindow;
  friend class DevWindow;
  friend class View;

protected:
  // Sniffer status
  pcap_if_t *allDev_ptr;
  std::vector<pcap_if_t *> allDev_vec;
  const char *dev; // device name
  pcap_t *handle;
  pcap_dumper_t *dumper;
  bpf_u_int32 mask;                        // net mask
  bpf_u_int32 net;                         // IP address
  flag_t status;                           // status {start, stop, restart}
  static std::vector<packet_struct *> pkt; // packet
  static View *view;                       // view
  pcap_dumper_t *dumpfile;
  std::promise<void> sniffing_thread_stopped;
  std::string fn;
  // const char *fn_c;

public:
  // Constructor for the Sniffer class
  Sniffer();
  ~Sniffer();
  bool findAllDevs(); // Find all available devices
  void getDevName(const char *devName); // Select a device to sniff
  bool getDevInfo();  // Open the device for sniffing
  void getView(View *viewObj);  // Get the view object
  void Select_dev(const char *devName); // Select a device to sniff
  void startSniffing(); // Start sniffing
  void stopSniffing();  // Stop sniffing
  void stop();  // Stop sniffing

private:
  // Callback function for pcap_loop
  static void get_packet(u_char *args, const struct pcap_pkthdr *header,
                         const u_char *packet); // Callback function for pcap_loop
  static void handle_ipv4(const u_char *packet, packet_struct *pkt_p);  // Handle IPv4 packet
  static void handle_arp(const u_char *packet, packet_struct *pkt_p); // Handle ARP packet
  static void handle_ipv6(const u_char *packet, packet_struct *pkt_p);  // Handle IPv6 packet

public slots:
  void sniff();
};

#endif // SNIFFER_H