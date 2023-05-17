#include "sniffer.h"
#include "utils/hdr.h"
#include "utils/utils.h"
#include <pcap/pcap.h>
#include <sys/types.h>
#include <thread>
#include <chrono>

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
    snifferThread.detach();

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

    return 0;
}
