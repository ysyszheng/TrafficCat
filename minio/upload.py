# upload pcap file to minio
import time
from minio import Minio

# Initialize the minio client object to connect to the minio service
# with the username and password (admin/password) as in the configuration file
minio_client = Minio(
    "127.0.0.1:9000", access_key="admin", secret_key="password", secure=False
)

# Path to uploaded files
pcap_path = "data/traffic.pcap"
json_path = "data/traffic.json"
label_path = "data/label.txt"
extractor_path = "data/extractor.txt"

# 获取系统时间,并转换为字符串,格式为:2021-01-01/00:00:00
time = time.strftime("%Y-%m-%d/%H:%M:%S", time.localtime())

# 判断桶是否存在,不存在则创建
# pcap桶
if not minio_client.bucket_exists("pcap"):
    minio_client.make_bucket("pcap")
# json桶
if not minio_client.bucket_exists("json"):
    minio_client.make_bucket("json")
# label桶
if not minio_client.bucket_exists("label"):
    minio_client.make_bucket("label")
# extractor桶
if not minio_client.bucket_exists("extractor"):
    minio_client.make_bucket("extractor")

# Upload file to minio
# 上传pcap文件，文件名为时间
minio_client.fput_object(bucket_name="pcap", object_name="time", file_path=pcap_path)
# 上传json文件，文件名为时间
minio_client.fput_object(bucket_name="json", object_name="time", file_path=json_path)
# 上传label文件，文件名为时间
minio_client.fput_object(bucket_name="label", object_name="time", file_path=label_path)
# 上传extractor文件，文件名为时间
minio_client.fput_object(bucket_name="extractor", object_name="time", file_path=extractor_path)