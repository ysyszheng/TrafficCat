#include "view.h"
#include "qchar.h"
#include "qobject.h"
#include "qtableview.h"
#include "utils/hdr.h"
#include <netinet/in.h>

/*
 * 0: No.
 * 1: Time
 * 2: Source
 * 3: Destination
 * 4: Protocol
 * 5: Length
 * 6: Info
 */
View::View(QTableView *table, QTextBrowser *text, QTreeView *tree)
    : table(table), tree(tree), text(text), index(0) {
  TableModel = new QStandardItemModel();
  TableModel->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("NO.")));
  TableModel->setHorizontalHeaderItem(1,
                                      new QStandardItem(QObject::tr("Time")));
  TableModel->setHorizontalHeaderItem(2,
                                      new QStandardItem(QObject::tr("Source")));
  TableModel->setHorizontalHeaderItem(
      3, new QStandardItem(QObject::tr("Destination")));
  TableModel->setHorizontalHeaderItem(
      4, new QStandardItem(QObject::tr("Protocol")));
  TableModel->setHorizontalHeaderItem(5,
                                      new QStandardItem(QObject::tr("Length")));
  TableModel->setHorizontalHeaderItem(6,
                                      new QStandardItem(QObject::tr("Info")));

  // set table
  table->setModel(TableModel);
  table->setColumnWidth(0, table->width() / 12);
  table->setColumnWidth(1, table->width() / 5);
  table->setColumnWidth(2, table->width() / 7);
  table->setColumnWidth(3, table->width() / 7);
  table->setColumnWidth(4, table->width() / 10);
  table->setColumnWidth(5, table->width() / 15);
  table->setColumnWidth(6, table->width() / 3.5);
  
  table->verticalHeader()->setVisible(false);
  table->setSelectionBehavior(QTableView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);

  // register meta type
  qRegisterMetaType<QList<QPersistentModelIndex>>(
      "QList<QPersistentModelIndex>");
  qRegisterMetaType<QAbstractItemModel::LayoutChangeHint>(
      "QAbstractItemModel::LayoutChangeHint");
  connect(table, SIGNAL(clicked(const QModelIndex &)), this,
          SLOT(onTableClicked(const QModelIndex &)));

  // set tree
  TreeModel = new QStandardItemModel();
  tree->setModel(TreeModel);
  tree->setEditTriggers(QAbstractItemView::NoEditTriggers);

  // set text
  text->setFont({"monospace"});
  text->setFontPointSize(10);
}

View::~View() {
  delete TableModel;
  delete TreeModel;
}

// clear all data
void View::add_pkt(const packet_struct *packet, bool flag) {
  if (!flag) 
    pkt.push_back(packet);

  QString prot, src, dst, info;

  // get protocol, source, destination, info
  switch (packet->net_type) {
  // ARP
  case ARP:
    prot = "ARP";
    info = (ntohs(packet->net_hdr.arp_hdr->opcode) == 1) ? "ARP Request"
                                                         : "ARP Reply";
    src = QString::fromStdString(
        ether_ntoa((const struct ether_addr *)&packet->eth_hdr->ether_shost));
    dst = QString::fromStdString(
        ether_ntoa((const struct ether_addr *)&packet->eth_hdr->ether_dhost));
    break;
  // IPv4
  case IPv4:
    src = QString::fromStdString(inet_ntoa(packet->net_hdr.ipv4_hdr->ip_src));
    dst = QString::fromStdString(inet_ntoa(packet->net_hdr.ipv4_hdr->ip_dst));
    break;
  // IPv6
  case IPv6:
    src = QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[0]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[1]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[2]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[3]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[4]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[5]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[6]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->src_addr[7]), 16);
    dst = QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[0]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[1]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[2]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[3]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[4]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[5]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[6]), 16) +
          ":" +
          QString::number(ntohs(packet->net_hdr.ipv6_hdr->dest_addr[7]), 16);
    break;
  default: // will never reach this
    return;
  }

  // get protocol, info
  if (packet->trs_type != Utrs) {
    switch (packet->trs_type) {
    // ICMP
    case ICMP:
      prot = "ICMP";
      break;
    // IGMP
    case IGMP:
      prot = "IGMP";
      break;
    // TCP
    case TCP:
      prot = "TCP";
      info = "Src port: " +
             QString::number(ntohs(packet->trs_hdr.tcp_hdr->th_sport)) +
             " to Dst port: " +
             QString::number(ntohs(packet->trs_hdr.tcp_hdr->th_dport));
      break;
    // UDP
    case UDP:
      prot = "UDP";
      info = "Src port: " +
             QString::number(ntohs(packet->trs_hdr.udp_hdr->src_port)) +
             " to Dst port: " +
             QString::number(ntohs(packet->trs_hdr.udp_hdr->dst_port));
      break;
    case Utrs:
      break;
    }
  } else {
    // get protocol
    switch (packet->net_type) {
    // ARP
    case ARP:
      prot = "ARP";
      break;
    // IPv4
    case IPv4:
      prot = "IPv4";
      break;
    // IPv6
    case IPv6:
      prot = "IPv6";
      break;
    case Unet: // will never reach this
      return;
    }
  }

  // display in TableView
  QStandardItem *item;
  // add row
  item = new QStandardItem(QString::number(packet->no));
  TableModel->setItem(index, 0, item);
  setColor(packet, item);
  // add time
  item = new QStandardItem(QString::fromStdString(packet->time));
  TableModel->setItem(index, 1, item);
  setColor(packet, item);
  // add source, destination, protocol, length, info
  item = new QStandardItem(src);
  TableModel->setItem(index, 2, item);
  setColor(packet, item);
  item = new QStandardItem(dst);
  TableModel->setItem(index, 3, item);
  setColor(packet, item);
  item = new QStandardItem(prot);
  TableModel->setItem(index, 4, item);
  setColor(packet, item);
  item = new QStandardItem(QString::number(packet->len));
  TableModel->setItem(index, 5, item);
  setColor(packet, item);
  item = new QStandardItem(info);
  TableModel->setItem(index, 6, item);
  setColor(packet, item);

  table->scrollToBottom();

  index++;
}

/* set different color according to protocal */
void View::setColor(const packet_struct* packet, QStandardItem *item) {
  if(packet->trs_type != Utrs) {
    // set color
      switch(packet->trs_type) {
          case TCP: item->setBackground(QBrush(QColor(255, 240, 245))); break;
          case UDP: item->setBackground(QBrush(QColor(255, 255, 240))); break;
          case ICMP:item->setBackground(QBrush(QColor(64 , 224, 208))); break;
          case IGMP:item->setBackground(QBrush(QColor(135, 206, 250))); break;
          case Utrs:break;
      }
  }else {
    // set color
      switch(packet->net_type) {
          case IPv4:item->setBackground(QBrush(QColor(250, 128, 114))); break;
          case IPv6:item->setBackground(QBrush(QColor(152, 251, 152))); break;
          case ARP: item->setBackground(QBrush(QColor(238, 130, 238))); break;
          case Unet:break;
      }
  }
}

/* set different color according to protocal */
void View::onTableClicked(const QModelIndex &item) {
  auto idx = item.row();
  if (!item.isValid()) {
    return;
  }
  idx = TableModel->item(idx, 0)->text().toInt() - 1;
  // LOG(idx);

  // clear text
  text->clear();
  text->insertPlainText(QString::fromStdString(
      store_payload((u_char *)pkt[idx]->eth_hdr, pkt[idx]->len)));

  // clear tree
  TreeModel->clear();
  const packet_struct *pkt_item = pkt[idx]; // TODO: packet content changed ?
  QStandardItem *child;

  // add frame information
  auto frame = new QStandardItem(QObject::tr("Frame Information"));
  TreeModel->setItem(0, frame);
  child = new QStandardItem(QObject::tr("Arrival Time: ") +
                            QString::fromStdString(pkt_item->time));
  frame->appendRow(child);
  child = new QStandardItem(QObject::tr("Frame Number: ") +
                            QString::number(pkt_item->no));
  frame->appendRow(child);
  child = new QStandardItem(
      QObject::tr("Frame Length: ") + QString::number(pkt_item->len) +
      QObject::tr(" bytes (") + QString::number(pkt_item->len * 8) +
      QObject::tr(" bits)"));
  frame->appendRow(child);

  // add ethernet information
  auto eth = new QStandardItem(QObject::tr("Ethernet II"));
  TreeModel->setItem(1, eth);
  child = new QStandardItem(
      QObject::tr("Destination: ") +
      QString::fromStdString(ether_ntoa(
          (const struct ether_addr *)&pkt_item->eth_hdr->ether_dhost)));
  eth->appendRow(child);
  child = new QStandardItem(
      QObject::tr("Source: ") +
      QString::fromStdString(ether_ntoa(
          (const struct ether_addr *)&pkt_item->eth_hdr->ether_shost)));
  eth->appendRow(child);
  // add type
  switch (pkt_item->net_type) {
  case IPv4:
    child = new QStandardItem(QObject::tr("Type: IPv4 (0x0800)"));
    break;
  case IPv6:
    child = new QStandardItem(QObject::tr("Type: IPv6 (0x86dd)"));
    break;
  case ARP:
    child = new QStandardItem(QObject::tr("Type: ARP (0x0806)"));
    break;
  case Unet: // will never reach this
    return;
  }
  eth->appendRow(child);

  // add network information
  QStandardItem *net;
  switch (pkt_item->net_type) {
  // IPv4
  case IPv4:
    net = new QStandardItem(QObject::tr("Internet Protocol Version 4"));
    // add network information
    TreeModel->setItem(2, net);

    // add version
    child =
        new QStandardItem(QObject::tr("Version: ") +
                          QString::number(IPv4_V(pkt_item->net_hdr.ipv4_hdr)));
    net->appendRow(child);

    // add header length
    child = new QStandardItem(
        QObject::tr("Internet Header Length: ") +
        QString::number(IPv4_HL(pkt_item->net_hdr.ipv4_hdr)) + ", length: " +
        QString::number(IPv4_HL(pkt_item->net_hdr.ipv4_hdr) * 32 / 8) +
        " bytes (" + QString::number(IPv4_HL(pkt_item->net_hdr.ipv4_hdr) * 32) +
        " bits)");
    net->appendRow(child);

    // add Differentiated Services Field
    child = new QStandardItem(
        QObject::tr("Differentiated Services Field: ") +
        QString("0x%1").arg(pkt_item->net_hdr.ipv4_hdr->ip_tos, 2, 16,
                            QLatin1Char('0')));
    net->appendRow(child);

    // add Differentiated Services Codepoint
    child = new QStandardItem(
        QObject::tr("Total Length: ") +
        QString::number(ntohs(pkt_item->net_hdr.ipv4_hdr->ip_len)) + " bytes");
    net->appendRow(child);

    // add Identification
    child = new QStandardItem(
        QObject::tr("Identification: ") +
        QString::number(ntohs(pkt_item->net_hdr.ipv4_hdr->ip_id)));
    net->appendRow(child);

    // add Flags
    child = new QStandardItem(
        QObject::tr("Flags: ") + "Reserved: " +
        ((ntohs(pkt_item->net_hdr.ipv4_hdr->ip_off) & IP_RF) ? "1" : "0") +
        ", Don't Fragement: " +
        ((ntohs(pkt_item->net_hdr.ipv4_hdr->ip_off) & IP_DF) ? "1" : "0") +
        ", More Fragement: " +
        ((ntohs(pkt_item->net_hdr.ipv4_hdr->ip_off) & IP_MF) ? "1" : "0"));
    net->appendRow(child);

    // add Fragment Offset
    child = new QStandardItem(
        QObject::tr("Fragment Offset: ") +
        QString::number(ntohs(pkt_item->net_hdr.ipv4_hdr->ip_off) &
                        IP_OFFMASK)); // TODO
    net->appendRow(child);

    // add Time To Live
    child =
        new QStandardItem(QObject::tr("Time To Live: ") +
                          QString::number(pkt_item->net_hdr.ipv4_hdr->ip_ttl));
    net->appendRow(child);

    // add Protocol
    child =
        new QStandardItem(QObject::tr("Protocol: ") +
                          QString::number(pkt_item->net_hdr.ipv4_hdr->ip_p));
    net->appendRow(child);

    // add Header Checksum
    child = new QStandardItem(
        QObject::tr("Header Checksum: ") +
        QString("0x%1").arg(ntohs(pkt_item->net_hdr.ipv4_hdr->ip_sum), 4, 16,
                            QLatin1Char('0')));
    net->appendRow(child);

    // add Source IP Address
    child = new QStandardItem(
        QObject::tr("Source IP Address: ") +
        QString::fromStdString(inet_ntoa(pkt_item->net_hdr.ipv4_hdr->ip_src)));
    net->appendRow(child);

    // add Destination IP Address
    child = new QStandardItem(
        QObject::tr("Destination IP Address: ") +
        QString::fromStdString(inet_ntoa(pkt_item->net_hdr.ipv4_hdr->ip_dst)));
    net->appendRow(child);
    break;
  
  // IPv6
  case IPv6:
    net = new QStandardItem(QObject::tr("Internet Protocol Version 6"));
    TreeModel->setItem(2, net);

    // add network information
    child = new QStandardItem(
        QObject::tr("Version: ") +
        QString::number(pkt_item->net_hdr.ipv6_hdr->vtc >> 4));
    net->appendRow(child);

    // add Traffic Class
    child = new QStandardItem(
        QObject::tr("Traffic Class: ") +
        QString("0x%1").arg(pkt_item->net_hdr.ipv6_hdr->vtc & 0x0f, 1, 16,
                            QLatin1Char('0')) +
        QString("%1").arg(pkt_item->net_hdr.ipv6_hdr->tcf >> 4, 1, 16,
                          QLatin1Char('0')));
    net->appendRow(child);

    // add Flow Label
    child = new QStandardItem(
        QObject::tr("Flow Label: ") +
        QString("0x%1").arg((pkt_item->net_hdr.ipv6_hdr->tcf & 0x0f) << 16 |
                                ntohs(pkt_item->net_hdr.ipv6_hdr->flow),
                            5, 16, QLatin1Char('0')));
    net->appendRow(child);

    // add Payload Length
    child = new QStandardItem(
        QObject::tr("Payload Length: ") +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->payload_len)));
    net->appendRow(child);

    // add Next Header
    child = new QStandardItem(
        QObject::tr("Next Header: ") +
        QString::number(pkt_item->net_hdr.ipv6_hdr->next_header));
    net->appendRow(child);

    // add Hop Limit
    child = new QStandardItem(
        QObject::tr("Hop Limit: ") +
        QString::number(pkt_item->net_hdr.ipv6_hdr->hop_limit));
    net->appendRow(child);

    // add Source Address
    child = new QStandardItem(
        QObject::tr("Source Address: ") +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[0]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[1]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[2]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[3]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[4]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[5]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[6]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->src_addr[7]), 16));
    net->appendRow(child);

    // add Destination Address
    child = new QStandardItem(
        QObject::tr("Source Address: ") +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[0]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[1]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[2]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[3]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[4]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[5]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[6]), 16) +
        ":" +
        QString::number(ntohs(pkt_item->net_hdr.ipv6_hdr->dest_addr[7]), 16));
    net->appendRow(child);
    break;
  
  // ARP
  case ARP:
    net = new QStandardItem(QObject::tr("Address Resolution Protocol"));
    TreeModel->setItem(2, net);

    // add Hardware Type
    child = new QStandardItem(
        QObject::tr("Hardware Type: ") +
        QString::number(ntohs(pkt_item->net_hdr.arp_hdr->hard_type)));
    net->appendRow(child);

    // add Protocol Type
    child = new QStandardItem(
        QObject::tr("Protocol Type: ") +
        QString("0x%1").arg(ntohs(pkt_item->net_hdr.arp_hdr->pro_type), 4, 16,
                            QLatin1Char('0')));
    net->appendRow(child);

    // add Hardware Address Length
    child = new QStandardItem(
        QObject::tr("Hardware Address Length: ") +
        QString::number(pkt_item->net_hdr.arp_hdr->hard_adr_len));
    net->appendRow(child);

    // add Protocol Address Length
    child = new QStandardItem(
        QObject::tr("Protocol Address Length: ") +
        QString::number(pkt_item->net_hdr.arp_hdr->pro_adr_len));
    net->appendRow(child);

    // add Operation
    child = new QStandardItem(
        QObject::tr("Operation: ") +
        QString::number(ntohs(pkt_item->net_hdr.arp_hdr->opcode)));
    net->appendRow(child);

    // add Sender Hardware Address
    child = new QStandardItem(
        QObject::tr("Sender Hardware Address: ") +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->src_mac[0], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->src_mac[1], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->src_mac[2], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->src_mac[3], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->src_mac[4], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->src_mac[5], 0, 16));
    net->appendRow(child);

    // add Sender Protocol Address
    child = new QStandardItem(
        QObject::tr("Sender Protocol Address: ") +
        QString::number(pkt_item->net_hdr.arp_hdr->src_ip[0]) + "." +
        QString::number(pkt_item->net_hdr.arp_hdr->src_ip[1]) + "." +
        QString::number(pkt_item->net_hdr.arp_hdr->src_ip[2]) + "." +
        QString::number(pkt_item->net_hdr.arp_hdr->src_ip[3]));
    net->appendRow(child);

    // add Target Hardware Address
    child = new QStandardItem(
        QObject::tr("Target Hardware Address: ") +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->dest_mac[0], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->dest_mac[1], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->dest_mac[2], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->dest_mac[3], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->dest_mac[4], 0, 16) + ":" +
        QString("%1").arg(pkt_item->net_hdr.arp_hdr->dest_mac[5], 0, 16));
    net->appendRow(child);

    // add Target Protocol Address
    child = new QStandardItem(
        QObject::tr("Target Protocol Address: ") +
        QString::number(pkt_item->net_hdr.arp_hdr->dest_ip[0]) + "." +
        QString::number(pkt_item->net_hdr.arp_hdr->dest_ip[1]) + "." +
        QString::number(pkt_item->net_hdr.arp_hdr->dest_ip[2]) + "." +
        QString::number(pkt_item->net_hdr.arp_hdr->dest_ip[3]));
    net->appendRow(child);
    break;
  case Unet: // will never reach this
    return;
  }

  // Transport Layer
  QStandardItem *trs;
  switch (pkt_item->trs_type) {
  case ICMP:
    trs = new QStandardItem(QObject::tr("Internet Control Message Protocol"));
    TreeModel->setItem(3, trs);

    // add Type
    child =
        new QStandardItem(QObject::tr("Type: ") +
                          QString::number(pkt_item->trs_hdr.icmp_hdr->type));
    trs->appendRow(child);

    // add Code
    child =
        new QStandardItem(QObject::tr("Code: ") +
                          QString::number(pkt_item->trs_hdr.icmp_hdr->code));
    trs->appendRow(child);

    // add Checksum
    child = new QStandardItem(
        QObject::tr("Checksum: ") +
        QString("0x%1").arg(ntohs(pkt_item->trs_hdr.icmp_hdr->check_sum), 4, 16,
                            QLatin1Char('0')));
    trs->appendRow(child);

    // add Rest Of Header
    child = new QStandardItem(
        QObject::tr("Rest Of Header: ") +
        QString("0x%1").arg(ntohl(pkt_item->trs_hdr.icmp_hdr->rst_of_header), 8,
                            16, QLatin1Char('0')));
    trs->appendRow(child);
    break;
  // case TCP:
  case IGMP:
    trs = new QStandardItem(QObject::tr("Internet Group Management Protocol"));
    TreeModel->setItem(3, trs);

    // add Type
    child =
        new QStandardItem(QObject::tr("Type: ") +
                          QString("0x%1").arg(pkt_item->trs_hdr.igmp_hdr->type,
                                              2, 16, QLatin1Char('0')));
    trs->appendRow(child);

    // add Max Resp Time
    child = new QStandardItem(
        QObject::tr("Max Resp Time: ") +
        QString("0x%1").arg(pkt_item->trs_hdr.igmp_hdr->resp_time, 2, 16,
                            QLatin1Char('0')));
    trs->appendRow(child);

    // add Checksum
    child = new QStandardItem(
        QObject::tr("Checksum: ") +
        QString("0x%1").arg(ntohs(pkt_item->trs_hdr.igmp_hdr->checksum), 4, 16,
                            QLatin1Char('0')));
    trs->appendRow(child);

    // add Group Address
    child = new QStandardItem(
        QObject::tr("Group Address: ") +
        QString::number(pkt_item->trs_hdr.igmp_hdr->group_addr[0]) + "." +
        QString::number(pkt_item->trs_hdr.igmp_hdr->group_addr[1]) + "." +
        QString::number(pkt_item->trs_hdr.igmp_hdr->group_addr[2]) + "." +
        QString::number(pkt_item->trs_hdr.igmp_hdr->group_addr[3]));
    trs->appendRow(child);
    break;
  // UDP
  case UDP:
    trs = new QStandardItem(QObject::tr("User Datagram Protocol"));
    TreeModel->setItem(3, trs);

    // add Source Port
    child = new QStandardItem(
        QObject::tr("Source Port: ") +
        QString::number(ntohs(pkt_item->trs_hdr.udp_hdr->src_port)));
    trs->appendRow(child);

    // add Destination Port
    child = new QStandardItem(
        QObject::tr("Destination Port: ") +
        QString::number(ntohs(pkt_item->trs_hdr.udp_hdr->dst_port)));
    trs->appendRow(child);

    // add Length
    child = new QStandardItem(
        QObject::tr("Length: ") +
        QString::number(ntohs(pkt_item->trs_hdr.udp_hdr->length)));
    trs->appendRow(child);

    // add Checksum
    child = new QStandardItem(
        QObject::tr("Checksum: ") +
        QString("0x%1").arg(ntohs(pkt_item->trs_hdr.udp_hdr->check_sum), 4, 16,
                            QLatin1Char('0')));
    trs->appendRow(child);
    break;

  // TCP
  case TCP:
    trs = new QStandardItem(QObject::tr("Transmission Control Protocol"));
    TreeModel->setItem(3, trs);

    // add Source Port
    child = new QStandardItem(
        QObject::tr("Source Port: ") +
        QString::number(ntohs(pkt_item->trs_hdr.tcp_hdr->th_sport)));
    trs->appendRow(child);

    // add Destination Port
    child = new QStandardItem(
        QObject::tr("Destination Port: ") +
        QString::number(ntohs(pkt_item->trs_hdr.tcp_hdr->th_dport)));
    trs->appendRow(child);

    // add Sequence Number
    child = new QStandardItem(
        QObject::tr("Sequence Number: ") +
        QString::number(ntohl(pkt_item->trs_hdr.tcp_hdr->th_seq)));
    trs->appendRow(child);

    // add Acknowledgment Number
    child = new QStandardItem(
        QObject::tr("Acknowledgment Number: ") +
        QString::number(ntohl(pkt_item->trs_hdr.tcp_hdr->th_ack)));
    trs->appendRow(child);

    // add Data Offset
    child = new QStandardItem(
        QObject::tr("Data Offset: ") +
        QString::number(TH_OFF(pkt_item->trs_hdr.tcp_hdr)) +
        " (Header Length: " +
        QString::number(TH_OFF(pkt_item->trs_hdr.tcp_hdr) * 4) + " bytes)");
    trs->appendRow(child);

    // add Reserved
    child = new QStandardItem(
        QObject::tr("Reverse: ") +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_offx2 & 0x08) >> 3) +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_offx2 & 0x04) >> 2) +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_offx2 & 0x02) >> 1));
    trs->appendRow(child);

    // add Flags
    child = new QStandardItem(
        QObject::tr("Flags: NS: ") +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_offx2 & 0x01)) +
        ", CWR: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_CWR) >> 7) +
        ", ECE: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_ECE) >> 6) +
        ", URG: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_URG) >> 5) +
        ", ACK: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_ACK) >> 4) +
        ", PSH: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_PUSH) >> 3) +
        ", RST: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_RST) >> 2) +
        ", SYN: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_SYN) >> 1) +
        ", FIN: " +
        QString::number((pkt_item->trs_hdr.tcp_hdr->th_flags & TH_FIN)));
    trs->appendRow(child);

    // add Window Size
    child = new QStandardItem(
        QObject::tr("Window Size: ") +
        QString::number(ntohs(pkt_item->trs_hdr.tcp_hdr->th_win)));
    trs->appendRow(child);

    // add Checksum
    child = new QStandardItem(
        QObject::tr("Checksum: ") +
        QString("0x%1").arg(ntohs(pkt_item->trs_hdr.tcp_hdr->th_sum), 4, 16,
                            QLatin1Char('0')));
    trs->appendRow(child);

    // add Urgent Pointer
    child = new QStandardItem(
        QObject::tr("Urgent Pointer: ") +
        QString::number(ntohs(pkt_item->trs_hdr.tcp_hdr->th_urp)));
    trs->appendRow(child);
    break;
  case Utrs:
    break;
  }
}

/*
 * 0: No.
 * 1: Time
 * 2: Source
 * 3: Destination
 * 4: Protocol
 * 5: Length
 * 6: Info
 */
void View::clearView() {
  TreeModel->clear();
  text->clear();

  TableModel->clear();

  // set tableview
  TableModel = new QStandardItemModel();
  TableModel->setHorizontalHeaderItem(0, new QStandardItem(QObject::tr("NO.")));
  TableModel->setHorizontalHeaderItem(1,
                                      new QStandardItem(QObject::tr("Time")));
  TableModel->setHorizontalHeaderItem(2,
                                      new QStandardItem(QObject::tr("Source")));
  TableModel->setHorizontalHeaderItem(
      3, new QStandardItem(QObject::tr("Destination")));
  TableModel->setHorizontalHeaderItem(
      4, new QStandardItem(QObject::tr("Protocol")));
  TableModel->setHorizontalHeaderItem(5,
                                      new QStandardItem(QObject::tr("Length")));
  TableModel->setHorizontalHeaderItem(6,
                                      new QStandardItem(QObject::tr("Info")));

  // set tableview
  table->setModel(TableModel);
  table->setColumnWidth(0, table->width() / 12);
  table->setColumnWidth(1, table->width() / 5);
  table->setColumnWidth(2, table->width() / 7);
  table->setColumnWidth(3, table->width() / 7);
  table->setColumnWidth(4, table->width() / 10);
  table->setColumnWidth(5, table->width() / 15);
  table->setColumnWidth(6, table->width() / 3.5);

  table->verticalHeader()->setVisible(false);
  table->setSelectionBehavior(QTableView::SelectRows);
  table->setSelectionMode(QAbstractItemView::SingleSelection);
  table->setEditTriggers(QAbstractItemView::NoEditTriggers);

  index = 0;
}