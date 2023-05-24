#ifndef DEVWINDOW_H
#define DEVWINDOW_H

#include "./utils/utils.h"
#include "sniffer.h"

// Device selection window
class DevWindow : public QDialog {
  Q_OBJECT
public:
// Constructor for the DevWindow class
  explicit DevWindow(Sniffer *snifferObj, QWidget *parent = nullptr);
  ~DevWindow();

signals:
// Signal for the sub window closed
  void subWndClosed();

private slots:
// Slot for the clicked signal
  void onClicked();
  void onToggled(bool checked);

private:
// Pointer to the Sniffer object
  Sniffer *sniffer;
  QGroupBox *devChoice;
  QRadioButton *selected;
  QGroupBox *creatDevChoice();
};

#endif // DEVWINDOW_H