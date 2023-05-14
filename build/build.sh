#! /bin/bash
qmake -o Makefile ./trafficat.pro
make
chmod +x ./bin/trafficat