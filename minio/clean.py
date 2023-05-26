"""
This script is used to clean the minio server.
"""

from minio import Minio

# Initialize the minio client object to connect to the minio service
# with the username and password (admin/password) as in the configuration file
minio_client = Minio(
    "127.0.0.1:9001", access_key="minioadmin", secret_key="minioadmin", secure=False
)

# Delete the file
# Delete the pcap file
if minio_client.bucket_exists("pcap"):
    for file in minio_client.list_objects("pcap"):
        minio_client.remove_object("pcap", file.object_name)
# Delete the json file
if minio_client.bucket_exists("json"):
    for file in minio_client.list_objects("json"):
        minio_client.remove_object("json", file.object_name)
# Delete the label file
if minio_client.bucket_exists("label"):
    for file in minio_client.list_objects("label"):
        minio_client.remove_object("label", file.object_name)
# Delete the extractor file
if minio_client.bucket_exists("extractor"):
    for file in minio_client.list_objects("extractor"):
        minio_client.remove_object("extractor", file.object_name)


