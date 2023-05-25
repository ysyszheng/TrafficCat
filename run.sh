#!/bin/bash

# Run minio
nohup ~/minio/minio server --address :9001 --console-address :9002 ~/minio/data >~/minio/minio.log 2>&1 &

# convert .pcap to .json
tshark -r data/traffic.pcap -T json > data/traffic.json

# Run kdd99extractor and analysis
kdd/kdd99extractor data/traffic.pcap > data/extractor.txt
python3 kdd/inference/main.py

# upload data
python3 minio/upload.py

# Run web
streamlit run web/dashboard.py
