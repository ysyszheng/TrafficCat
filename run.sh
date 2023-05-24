#!/bin/bash

# convert .pcap to .json
tshark -r data/traffic.pcap -T json > data/traffic.json

# Run kdd99extractor and analysis
kdd/kdd99extractor data/traffic.pcap > data/extractor.txt
python3 kdd/inference/main.py

streamlit run web/dashboard.py
