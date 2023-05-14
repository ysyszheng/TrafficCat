#-------------------------------------------------
#
# Project created by QtCreator 2022-11-21T22:12:08
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ./bin/trafficat
TEMPLATE = app

CONFIG += C++11
LIBS += -lpcap

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        ../src/view.cpp \
        ../src/devwindow.cpp \
        ../src/main.cpp \
        ../src/mainwindow.cpp \
        ../src/catch.cpp \
        ../src/filter.cpp \
        ../src/sniffer.cpp \
        ../src/utils/utils.cpp

HEADERS += \
        ../src/view.h \
        ../src/devwindow.h \
        ../src/mainwindow.h \
        ../src/catch.h \
        ../src/sniffer.h \
        ../src/filter.h \
        ../src/utils/utils.h \
        ../src/utils/hdr.h

FORMS += \
        ../ui/mainwindow.ui