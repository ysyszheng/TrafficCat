#! /bin/bash
qmake -o Makefile ./clsniff.pro
make
chmod +x ./bin/clsniff