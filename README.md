TrafficCat
=====

Machine Learning Based Network Traffic Analysis and Audit System

Dependencies
-----
```bash
$> sudo apt install build-essential
$> sudo apt install qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools
$> sudo apt install libpcap-dev
```

Run with GUI
-----
```bash
$> cd build
$> chmod +x ./build.sh
$> ./bin/trafficat
```

Run with CLI
-----
```bash
$> cd build
$> chmod +x ./clsniff.sh
$> ./bin/clsniff
```

Run kdd99extractor
-----
```bash
$> sudo kdd/kdd99extractor
```

Run kdd99extractor and analysis
-----
```bash
$> sudo kdd/kdd99extractor > kdd/inference/input/output.txt
$> python3 kdd/inference/main.py
```
