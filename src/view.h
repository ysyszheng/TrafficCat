#ifndef VIEW_H
#define VIEW_H

#include "qobjectdefs.h"
#include "utils/utils.h"

class View : public QObject {
  // Macro to support Qt's meta-object system
  Q_OBJECT

private:
  QTableView *table;
  QTreeView *tree;
  QTextBrowser *text;

public:
  // Vector to store pointers to packet_struct objects
  std::vector<const packet_struct *> pkt;

  // Constructor
  View(QTableView *table, QTextBrowser *text, QTreeView *tree);
  ~View();

  // Method to add a packet to the view
  void add_pkt(const packet_struct *packete, bool flag=false);
  void clearView();  

private slots:
  // Slot to handle the click on a packet in the table
  void onTableClicked(const QModelIndex &);

protected:
  // Method to add a packet to the table
  friend class MainWindow;
  int index;
  QStandardItemModel *TableModel;
  QStandardItemModel *TreeModel;
  // Method to add a packet to the tree
  void setColor(const packet_struct* packet, QStandardItem *item);
};

#endif // VIEW_H