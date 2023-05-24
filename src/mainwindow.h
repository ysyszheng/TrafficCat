#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "devwindow.h"
#include "filter.h"
#include "sniffer.h"
#include "ui_mainwindow.h"
#include "utils/utils.h"
#include "view.h"

// Main window
namespace Ui {
class MainWindow;
}
class Filter;

class MainWindow : public QMainWindow {
  Q_OBJECT

public:
  // Constructor for the MainWindow class
  explicit MainWindow(QWidget *parent = nullptr);
  ~MainWindow();

private slots:
  // Slot for the clicked signal
  void showMainWnd();
  void start_catch();
  void stop_catch();
  void clear_catch();
  void on_filter_textChanged(const QString &arg1);
  void on_filter_Pressed();
  void save_file();
  void ip_reassemble();
  void file_reassemble();

signals:
  void sig();

private:
  Ui::MainWindow *ui;
  // sniffer
  Sniffer *sniffer;
  // catch thread
  QThread *cthread;
  // dev choice window
  DevWindow *devwindow;
  // views
  View *view;
  // menuBar
  void setMenuBar(QMenuBar *mBar);
  // filter
  Filter *filter;
};

#endif // MAINWINDOW_H
