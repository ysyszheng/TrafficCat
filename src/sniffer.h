#ifndef SNIFFER_H
#define SNIFFER_H

#include "catch.h"
#include "utils/hdr.h"
#include "utils/utils.h"
#include "view.h"
#include <pcap/pcap.h>

class Sniffer : public QObject {
  Q_OBJECT

  friend class MainWindow;
  friend class DevWindow;
  friend class View;

protected:
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
  const char *fn_c;

public:
  Sniffer();
  ~Sniffer();
  bool findAllDevs();
  void getDevName(const char *devName);
  bool getDevInfo();
  void getView(View *viewObj);

private:
  static void get_packet(u_char *args, const struct pcap_pkthdr *header,
                         const u_char *packet);
  static void handle_ipv4(const u_char *packet, packet_struct *pkt_p);
  static void handle_arp(const u_char *packet, packet_struct *pkt_p);
  static void handle_ipv6(const u_char *packet, packet_struct *pkt_p);

public slots:
  void sniff();
};

#endif // SNIFFER_H