# upload pcap file to minio
import time
from minio import Minio

# Initialize the minio client object to connect to the minio service
# with the username and password (admin/password) as in the configuration file
minio_client = Minio(
    "127.0.0.1:9001", access_key="minioadmin", secret_key="minioadmin", secure=False
)

# Path to uploaded files
pcap_path = "data/traffic.pcap"
json_path = "data/traffic.json"
label_path = "data/label.txt"
extractor_path = "data/extractor.txt"

# Get the system time and convert it to a string in the format: 2021.01.01_00:00:00
time_str = time.strftime("%Y.%m.%d_%H:%M:%S", time.localtime())

# Determine if a bucket exists, create if it does not
# bucket pcap
if not minio_client.bucket_exists("pcap"):
    minio_client.make_bucket("pcap")
# bucket json
if not minio_client.bucket_exists("json"):
    minio_client.make_bucket("json")
# bucket label
if not minio_client.bucket_exists("label"):
    minio_client.make_bucket("label")
# bucket extractor
if not minio_client.bucket_exists("extractor"):
    minio_client.make_bucket("extractor")

# Upload file to minio
# Upload pcap file with time as file name
minio_client.fput_object(bucket_name="pcap", object_name="pcap"+time_str, file_path=pcap_path)
# Upload json file with time as file name
minio_client.fput_object(bucket_name="json", object_name="json"+time_str, file_path=json_path)
# Upload the label file with the time as the file name
minio_client.fput_object(bucket_name="label", object_name="label"+time_str, file_path=label_path)
# Upload extractor file with time as file name
minio_client.fput_object(bucket_name="extractor", object_name="extractor"+time_str, file_path=extractor_path)