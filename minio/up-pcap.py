# upload pcap file to minio
import time
from minio import Minio

# Initialize the minio client object to connect to the minio service
# with the username and password (admin/password) as in the configuration file
minio_client = Minio(
    "127.0.0.1:9000", access_key="admin", secret_key="password", secure=False
)

# Path to uploaded files
uploadpath = "data/traffic.pcap"

# 获取系统时间,并转换为字符串,格式为:2021-01-01/00:00:00
time = time.strftime("%Y-%m-%d/%H:%M:%S", time.localtime())

# Upload a file to the pcap bucket in minio
minio_client.fput_object(bucket_name="pcap", object_name="time", file_path=uploadpath)
