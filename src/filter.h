#ifndef FILTER_H
#define FILTER_H

#include "sniffer.h"
#include "utils/utils.h"
#include <QTableView>
#include <map>
#include <regex>
#define P 0     /* protocal */
#define S 1     /* source IP */
#define D 2     /* dest IP */
#define SPORT 3 /* source port */
#define DPORT 4 /* dest port */
#define C 5     /* packet content */

// Filter window
class Filter : public QObject {
  Q_OBJECT
public:
  // Constructor for the Filter class
  Filter();
  ~Filter();
  bool checkCommand(QString command);
  bool loadCommand(QString command);
  void launchFilter(View *view);
  bool launchOneFilter(const packet_struct *packet);

private:
  // Query structure
  std::map<int, std::string> query;
  std::string findWord(std::string command, size_t pos);
};

#endif
