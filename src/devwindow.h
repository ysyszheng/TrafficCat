#ifndef DEVWINDOW_H
#define DEVWINDOW_H

#include "./utils/utils.h"
#include "sniffer.h"

class DevWindow : public QDialog {
  Q_OBJECT
public:
  explicit DevWindow(Sniffer *snifferObj, QWidget *parent = nullptr);
  ~DevWindow();

signals:
  void subWndClosed();

private slots:
  void onClicked();
  void onToggled(bool checked);

private:
  Sniffer *sniffer;
  QGroupBox *devChoice;
  QRadioButton *selected;
  QGroupBox *creatDevChoice();
};

#endif // DEVWINDOW_H