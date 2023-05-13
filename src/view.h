#ifndef VIEW_H
#define VIEW_H

#include "qobjectdefs.h"
#include "utils/utils.h"

class View : public QObject {
  Q_OBJECT

private:
  QTableView *table;
  QTreeView *tree;
  QTextBrowser *text;

public:
  std::vector<const packet_struct *> pkt;

  View(QTableView *table, QTextBrowser *text, QTreeView *tree);
  ~View();
  void add_pkt(const packet_struct *packete, bool flag=false);

  void clearView();  

private slots:
  void onTableClicked(const QModelIndex &);

protected:
  friend class MainWindow;
  int index;
  QStandardItemModel *TableModel;
  QStandardItemModel *TreeModel;

  void setColor(const packet_struct* packet, QStandardItem *item);
};

#endif // VIEW_H