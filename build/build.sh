#! /bin/bash
qmake -o Makefile ./sniffer.pro
make
chmod +x ./bin/sniffer