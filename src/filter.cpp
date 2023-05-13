#include "filter.h"
#include "utils/utils.h"

Filter::Filter() {}

Filter::~Filter() {}

/*
 * the format of commands should be: [-options] [data]
 * -p protocal / -s sourceIP / -d destIP / -sport sourcePort / -dport destPort /
 * -c packetContent using regex to check syntax
 */
bool Filter::checkCommand(QString command) {
  std::string pattern{"(-h)|(([ ]*((-p[ ]+[a-zA-Z]+)|((-s|-d)[ "
                      "]+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})|((-sport|-dport)["
                      " ]+\\d+)|(-c[ ]\\S+))[ ]+)*((-p[ ]+[a-zA-Z]+)|((-s|-d)[ "
                      "]+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})|((-sport|-dport)["
                      " ]+\\d+)|(-c[ ]\\S+))?)"};
  std::regex re(pattern);
  return std::regex_match(command.toStdString(), re);
}

/*
 * load correct command to query structure
 * prepare for function launchfilter()
 */
bool Filter::loadCommand(QString command) {
  query.clear();
  if (!checkCommand(command)) {
    return false;
  }

  std::string com = command.toStdString();
  std::size_t pos;
  pos = com.find("-p ");
  if (pos < com.size())
    query.insert(std::make_pair(P, findWord(com, pos + 2)));
  pos = com.find("-s ");
  if (pos < com.size())
    query.insert(std::make_pair(S, findWord(com, pos + 2)));
  pos = com.find("-d ");
  if (pos < com.size())
    query.insert(std::make_pair(D, findWord(com, pos + 2)));
  pos = com.find("-sport ");
  if (pos < com.size())
    query.insert(std::make_pair(SPORT, findWord(com, pos + 6)));
  pos = com.find("-dport ");
  if (pos < com.size())
    query.insert(std::make_pair(DPORT, findWord(com, pos + 6)));
  pos = com.find("-c ");
  if (pos < com.size())
    query.insert(std::make_pair(C, findWord(com, pos + 2)));
  return true;
}

std::string Filter::findWord(std::string command, size_t pos) {
  size_t beg = command.find_first_not_of(std::string(" "), pos);
  size_t end = command.find_first_of(std::string(" "), beg);
  if (end >= command.size())
    end = command.find_first_of(std::string("\n"), beg);

  return command.substr(beg, end - beg);
}

bool Filter::launchOneFilter(const packet_struct *tmpPacket) {
  QString src_IP = "";
  QString dest_IP = "";
  switch (tmpPacket->net_type) {
  case ARP: {
    int i;
    for (i = 0; i < 4; i++) {
      QString temp = QString::number(tmpPacket->net_hdr.arp_hdr->src_ip[i], 10);
      src_IP.append(temp);
      if (i < 3)
        src_IP.append('.');
    }
    for (i = 0; i < 4; i++) {
      QString temp =
          QString::number(tmpPacket->net_hdr.arp_hdr->dest_ip[i], 10);
      dest_IP.append(temp);
      if (i < 3)
        dest_IP.append('.');
    }
    break;
  }

  case IPv4:
    src_IP = inet_ntoa(tmpPacket->net_hdr.ipv4_hdr->ip_src);
    dest_IP = inet_ntoa(tmpPacket->net_hdr.ipv4_hdr->ip_dst);
    break;

  case IPv6: {
    int i;
    for (i = 0; i < 8; i++) {
      QString temp =
          QString::number(tmpPacket->net_hdr.ipv6_hdr->src_addr[i], 16);
      src_IP.append(temp);
      if (i < 7)
        src_IP.append(':');
    }
    for (i = 0; i < 8; i++) {
      QString temp =
          QString::number(tmpPacket->net_hdr.ipv6_hdr->dest_addr[i], 16);
      dest_IP.append(temp);
      if (i < 7)
        dest_IP.append(':');
    }
    break;
  }
  case Unet:
    break;
  }

  QString Protocal;

  switch (tmpPacket->trs_type) {
  case UDP:
    Protocal = "UDP";
    break;
  case TCP:
    Protocal = "TCP";
    break;
  case ICMP:
    Protocal = "ICMP";
    break;
  case IGMP:
    Protocal = "IGMP";
    break;
  case Utrs:
    break;
  }
  if (tmpPacket->trs_type == Utrs) {
    switch (tmpPacket->net_type) {
    case ARP:
      Protocal = "ARP";
      break;
    case IPv4:
      Protocal = "IPv4";
      break;
    case IPv6:
      Protocal = "IPv6";
      break;
    case Unet:
      break;
    default:
      break;
    }
  }

  bool flag = true;
  for (std::map<int, std::string>::iterator iQuery = query.begin();
       iQuery != query.end(); iQuery++) {
    switch (iQuery->first) {
    case P: {
      if (Protocal.toStdString().find(iQuery->second.data()) >
          Protocal.toStdString().length()) {
        flag = false;
      }
      break;
    }

    case S: {
      std::string tmpSource = src_IP.toStdString();
      tmpSource = tmpSource.substr(0, tmpSource.find_first_of(':'));
      if (iQuery->second.find(tmpSource.data()) != 0) {
        flag = false;
      }
      break;
    }

    case D: {
      std::string tmpDest = dest_IP.toStdString();
      tmpDest = tmpDest.substr(0, tmpDest.find_first_of(':'));
      if (iQuery->second.find(tmpDest.data()) != 0) {
        flag = false;
      }
      break;
    }

    case SPORT: {
      if (tmpPacket->trs_type == TCP) {
        std::string tmpSPort =
            std::to_string(ntohs(tmpPacket->trs_hdr.tcp_hdr->th_sport));
        if (iQuery->second.find(tmpSPort.data()) != 0) {
          flag = false;
        }
        break;
      } else if (tmpPacket->trs_type == UDP) {
        std::string tmpSPort =
            std::to_string(ntohs(tmpPacket->trs_hdr.udp_hdr->src_port));
        if (iQuery->second.find(tmpSPort.data()) != 0) {
          flag = false;
        }
        break;
      } else {
        flag = false;
        break;
      }
    }

    case DPORT: {
      if (tmpPacket->trs_type == TCP) {
        std::string tmpDPort =
            std::to_string(ntohs(tmpPacket->trs_hdr.tcp_hdr->th_dport));
        if (iQuery->second.find(tmpDPort.data()) != 0) {
          flag = false;
        }
        break;
      } else if (tmpPacket->trs_type == UDP) {
        std::string tmpDPort =
            std::to_string(ntohs(tmpPacket->trs_hdr.udp_hdr->dst_port));
        if (iQuery->second.find(tmpDPort.data()) != 0) {
          flag = false;
        }
        break;
      } else {
        flag = false;
        break;
      }
    }

    case C: {
      std::string text =
          store_content((u_char *)tmpPacket->eth_hdr, tmpPacket->len);
      if (text.find(iQuery->second) >= text.size()) {
        flag = false;
      }
      break;
    }
    }
    if (!flag)
      break;
  }

  return flag;
}

void Filter::launchFilter(View *view) {
  /* clear the tableView */
  view->clearView();
  int len = view->pkt.size();
  int i;
  bool flag;
  for (i = 0; i < len; ++i) {
    flag = launchOneFilter(view->pkt[i]);
    if (flag)
      view->add_pkt(view->pkt[i], true);
  }
}