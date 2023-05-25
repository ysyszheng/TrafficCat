#!/bin/bash

# Run minio
nohup ~/minio/minio server --address :9001 --console-address :9002 ~/minio/data >~/minio/minio.log 2>&1 &

# download data
python3 minio/download.py

# Run web
streamlit run web/dashboard.py
