#ifndef UTILS_H
#define UTILS_H

#include "hdr.h"
#include <QAction>
#include <QBrush>
#include <QByteArray>
#include <QDebug>
#include <QDialog>
#include <QFileDialog>
#include <QGroupBox>
#include <QHeaderView>
#include <QLineEdit>
#include <QList>
#include <QMainWindow>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QModelIndex>
#include <QPushButton>
#include <QRadioButton>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QString>
#include <QTableView>
#include <QTextBrowser>
#include <QThread>
#include <QTreeView>
#include <QVBoxLayout>
#include <QtGui>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <ctype.h>
#include <errno.h>
#include <iostream>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#define FALSE 0
#define TRUE 1

// Define print settings
#define PRINT_DEV_NAME TRUE
#define PRINT_DEV_INFO FALSE
#define PRINT_PACKAGE_NUM FALSE
#define PRINT_ETHER_ADDR FALSE
#define PRINT_UNKNOW_ETHER_TYPE FALSE
#define PRINT_UNKNOW_IP_PROTO FALSE
#define PRINT_UNKNOW_ARP_PROTO FALSE

// Macro for printing error information
#define ERROR_INFO(msg)                                                        \
  std::cout << "(" << __FILE__ << ":" << __LINE__ << ") " << __FUNCTION__      \
            << "(): " << msg << std::endl;
// Macro for logging information
#define LOG(msg)                                                               \
  std::cout << "(" << __FILE__ << ":" << __LINE__ << ") " << msg << std::endl;

// Enumeration for flag states
typedef enum { Init, Start, Stop } flag_t;

// Function to print the payload of a packet
void print_payload(const u_char *payload, size_t payload_len);
std::string store_payload(const u_char *payload, long payload_len);
std::string store_content(const u_char *payload, long payload_len);

// Function to compare IP packets based on their IP offsets
bool ipcmp(const packet_struct *a, const packet_struct *b);
// Function to get the current date and time as a string
const std::string currentDataTime();

#endif // UTILS_H