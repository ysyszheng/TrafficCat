#include "mainwindow.h"
#include "utils/hdr.h"
#include "utils/utils.h"

/*
 * Constructor for the MainWindow class
 *  parent Pointer to the parent widget
 */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
  // Ui config
  ui->setupUi(this);
  QMenuBar *mBar = menuBar();
  setMenuBar(mBar);
  setWindowTitle(tr("Trafficat"));

  QTableView *table = ui->tableView;
  QTextBrowser *text = ui->textBrowser;
  QTreeView *tree = ui->treeView;
  view = new View(table, text, tree);

  // catch thread
  cthread = new QThread;
  sniffer = new Sniffer();
  sniffer->moveToThread(cthread);
  sniffer->getView(view);
  connect(this, SIGNAL(sig()), sniffer, SLOT(sniff()));
  cthread->start();

  // filter
  filter = new Filter();
  connect(this->ui->filter_rule, SIGNAL(textChanged(const QString &)), this,
          SLOT(on_filter_textChanged(const QString &)));
  connect(this->ui->filterButton, SIGNAL(clicked()), this,
          SLOT(on_filter_Pressed()));

  // Device choice
  DevWindow *devwindow = new DevWindow(sniffer, this);
  devwindow->show();
  connect(devwindow, SIGNAL(subWndClosed()), this, SLOT(showMainWnd()));
}

/**
 * @brief Destructor for the MainWindow class
 */
MainWindow::~MainWindow() {
  delete ui;
  delete filter;
  delete sniffer;
  delete view;
}

// SLOT function
void MainWindow::showMainWnd() {
  LOG(sniffer->dev);
  char errbuf[PCAP_ERRBUF_SIZE];
  sniffer->handle = pcap_open_live(sniffer->dev, BUFSIZ, -1, 1000, errbuf);
  if (sniffer->handle == NULL) {
    ERROR_INFO(errbuf);
    exit(1);
  }

  emit sig();
  this->show();
}
// Filter
void MainWindow::start_catch() {
  LOG("Start");
  sniffer->status = Start;
}

void MainWindow::stop_catch() {
  LOG("Stop");
  sniffer->status = Stop;
  // on_filter_Pressed();
}

void MainWindow::clear_catch() {
  LOG("Clear");
  view->clearView();
}

/**
 * Save the captured packets to a file
 */
void MainWindow::setMenuBar(QMenuBar *mBar) {
  // QMenu *pFile = mBar->addMenu("Files");
  // QAction *pOpen = pFile->addAction("Open");
  // connect(pOpen, &QAction::triggered, [=]() { qDebug() << "Open"; });
  // pFile->addSeparator();
  // QAction *pSave = pFile->addAction("Save");
  // connect(pSave, &QAction::triggered, this, &MainWindow::save_file);

  // QMenu *pRun = mBar->addMenu("Run");
  QAction *pStart = mBar->addAction("Start");
  connect(pStart, &QAction::triggered, this, &MainWindow::start_catch);
  QAction *pStop = mBar->addAction("Stop");
  connect(pStop, &QAction::triggered, this, &MainWindow::stop_catch);
  QAction *pRestart = mBar->addAction("Clear");
  connect(pRestart, &QAction::triggered, this, &MainWindow::clear_catch);

  QAction *pSave = mBar->addAction("Save");
  connect(pSave, &QAction::triggered, this, &MainWindow::save_file);

  QMenu *pRe = mBar->addMenu("Reassemble");
  QAction *pIPre = pRe->addAction("IP Reassemble");
  connect(pIPre, &QAction::triggered, this, &MainWindow::ip_reassemble);
  // TODO:make IPassemble a QCheckBox, change sniffer.is_IPreassmble_ticked to
  // true if ticked.
  pRe->addSeparator();
  QAction *pFre = pRe->addAction("File Reassemble");
  connect(pFre, &QAction::triggered, this, &MainWindow::file_reassemble);
}

/*
 * filter control functions
 * when text changes, check the syntax.
 * when Filter button is pressed.
 */
void MainWindow::on_filter_textChanged(const QString &command) {
  QLineEdit *le = ui->filter_rule;
  if (filter->checkCommand(command)) {
    le->setStyleSheet("QLineEdit {background-color: #AFE1AF;}");
  } else {
    le->setStyleSheet("QLineEdit {background-color: #FAA0A0;}");
  }
}

/**
 * MainWindow::on_filter_Pressed
 * when filter button is pressed, load the command and launch the filter.
 */
void MainWindow::on_filter_Pressed() {
  if (ui->filter_rule->text() == tr("-h")) {
    QMessageBox::about(this, tr("The Usage of filter"),
                       tr("<-options>\t<filter rule>\n"
                          "-h\thelp\n-p\tprotocol\n-s\tsource IP "
                          "address\n-d\tdestination IP address\n"
                          "-sport\tsource port\n-dport\tdestination "
                          "port\n-c\tpacket content"));
    return;
  }
  filter->loadCommand(ui->filter_rule->text());
  filter->launchFilter(view);
}

/**
 * MainWindow::ip_reassemble
 * reassemble the IP packets
 */
void MainWindow::save_file() {
  LOG("Save file");
  QDateTime time = QDateTime::currentDateTime();
  QString dateTime = time.toString("MM-dd_hh-mm-ss");
  QString timeName = QString("%1.log").arg(dateTime);

  // get file name 
  QString fileName = QFileDialog::getSaveFileName(
      this, tr("Save Network Packet"), "../test/log/" + timeName,
      tr("Log File (*.log);;All Files (*)"));
  // if file name is empty, return
  if (fileName.isEmpty())
    return;
  else { 
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
      QMessageBox::information(this, tr("Unable to open file"),
                               file.errorString());
      return;
    }
    // QDataStream out(&file);
    // out.setVersion(QDataStream::Qt_4_5);
    QTextStream out(&file);
    out.setCodec("UTF-8");
    // out << QString::fromStdString("Time: ").toUtf8()
    sniffer->status = Stop; 

    // write the packets to the file
    for (auto &pkt : view->pkt) {
      out << QString::fromStdString("Time: ").toUtf8()
          << QString::fromStdString(pkt->time).toUtf8()
          << QString::fromStdString("\n").toUtf8()
          << QString::fromStdString("NO: ").toUtf8()
          << QString::number(pkt->no).toUtf8()
          << QString::fromStdString("\n").toUtf8()
          << QString::fromStdString(
                 store_payload((u_char *)pkt->eth_hdr, pkt->len))
                 .toUtf8()
          << QString::fromStdString("\n").toUtf8();
    }
    sniffer->status = Start;
    
  }
}

/* IP reassmble function */
void MainWindow::ip_reassemble() {
  // get the selected packet
  QItemSelectionModel *select = ui->tableView->selectionModel();

  // if no packet is selected, return
  if (select->selectedRows().empty()) {
    QMessageBox::critical(this, tr("Warning"), tr("Please select a packet"));
    return;
  } else {
    // get the row number of the selected packet
    int row = select->selectedIndexes().at(0).row();
    const packet_struct *packet = view->pkt[row];
    // check if the packet is a IP packet
    if (packet->net_type != IPv4) {
      QMessageBox::critical(this, tr("Warning"), tr("Not a IP packet"));
    } else if (((ntohs(packet->net_hdr.ipv4_hdr->ip_off) & IP_DF) >> 14) == 1) {
      QMessageBox::critical(this, tr("Warning"), tr("Not a Fragment packet"));
    } else {
      // clear the textBrowser
      ui->textBrowser->clear();
      int len;
      int iplen = IPv4_HL(packet->net_hdr.ipv4_hdr) * 4;
      void *content, *content_new;
      std::vector<const packet_struct *> repkt;
      uint16_t id = ntohs(packet->net_hdr.ipv4_hdr->ip_id);
      // find all the packets with the same id
      for (auto &item : view->pkt) {
        if (ntohs(item->net_hdr.ipv4_hdr->ip_id) == id) {
          repkt.push_back(item);
        }
      }
      // sort the packets by offset
      sort(repkt.begin(), repkt.end(), ipcmp);
      // allocate memory for the reassembled packet
      content = malloc(
          repkt.back()->len +
          (ntohs(repkt.back()->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) * 8);
      switch (packet->trs_type) {
      // if the packet is a TCP packet
      case TCP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          // if the packet is the first fragment
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            memcpy(content, item->trs_hdr.tcp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.tcp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      // if the packet is a UDP packet
      case UDP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          // if the packet is the first fragment
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            memcpy(content, item->trs_hdr.udp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.udp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      // if the packet is a ICMP packet
      case ICMP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          // if the packet is the first fragment
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            memcpy(content, item->trs_hdr.icmp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.icmp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      // if the packet is a IGMP packet
      case IGMP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          // if the packet is the first fragment
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            memcpy(content, item->trs_hdr.igmp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.igmp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      case Utrs:
        break;
      }
      ui->textBrowser->insertPlainText(
          QString::fromStdString(store_payload((u_char *)content, len)));
    }
    return;
  }
}

/* file reassmble function */
void MainWindow::file_reassemble() {
  // check if the packet is selected
  QItemSelectionModel *select = ui->tableView->selectionModel();
  if (select->selectedRows().empty()) {
    QMessageBox::critical(this, tr("Warning"), tr("Please select a packet"));
    return;
  } else {

    // check if the packet is a TCP packet
    int row = select->selectedIndexes().at(0).row();
    const packet_struct *packet = view->pkt[row];
    if (packet->trs_type != TCP) {
      QMessageBox::critical(this, tr("Warning"), tr("Not a TCP packet"));
    } else if (((ntohs(packet->net_hdr.ipv4_hdr->ip_off) & IP_DF) >> 14) == 1) {
      QMessageBox::critical(this, tr("Warning"), tr("Not a Fragment packet"));
    } else {
      // clear the text browser
      ui->textBrowser->clear();
      int len;
      int iplen = IPv4_HL(packet->net_hdr.ipv4_hdr) * 4;
      void *content, *content_new;
      std::vector<const packet_struct *> repkt;

      // find all the fragments of the packet
      uint16_t id = ntohs(packet->net_hdr.ipv4_hdr->ip_id);
      for (auto &item : view->pkt) {
        if (ntohs(item->net_hdr.ipv4_hdr->ip_id) == id) {
          repkt.push_back(item);
        }
      }

      // sort the fragments
      sort(repkt.begin(), repkt.end(), ipcmp);
      content = malloc(
          repkt.back()->len +
          (ntohs(repkt.back()->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) * 8);
      switch (packet->trs_type) {
      // if the packet is a TCP packet
      case TCP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          // if the packet is the first fragment
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            memcpy(content, item->trs_hdr.tcp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.tcp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      // if the packet is a UDP packet
      case UDP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            // if the packet is the first fragment
            memcpy(content, item->trs_hdr.udp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.udp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      // if the packet is a ICMP packet
      case ICMP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            // if the packet is the first fragment
            memcpy(content, item->trs_hdr.icmp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.icmp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      // if the packet is a IGMP packet
      case IGMP:
        for (auto &item : repkt) {
          LOG((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK));
          if ((ntohs(item->net_hdr.ipv4_hdr->ip_off) & IP_OFFMASK) == 0) {
            // if the packet is the first fragment
            memcpy(content, item->trs_hdr.igmp_hdr,
                   item->len - SIZE_ETHERNET - iplen);
            len = item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          } else {
            // if the packet is not the first fragment
            memcpy(content_new, (u_char *)(item->trs_hdr.igmp_hdr),
                   item->len - SIZE_ETHERNET - iplen);
            len += item->len - SIZE_ETHERNET - iplen;
            content_new = (u_char *)content + len;
          }
        }
        break;
      case Utrs:
        break;
      }
      ui->textBrowser->insertPlainText(
          QString::fromStdString(store_payload((u_char *)content, len)));
    }
    return;
  }
}