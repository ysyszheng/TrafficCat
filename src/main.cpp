#include "mainwindow.h"
#include <QApplication>

/**
 * @brief Main function
 * @param argc Number of command line arguments
 * @param argv Command line arguments
 * @return Exit status
 */
int main(int argc, char *argv[]) {
  QApplication a(argc, argv);
  MainWindow w;
  // w.show();

  return a.exec();
}
