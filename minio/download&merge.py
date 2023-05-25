# 从minio下载json桶、label桶、extractor桶中的所有对象，并将每个桶中的对象合并为一个文件


import os
from minio import Minio


# Initialize the minio client object to connect to the minio service
# with the username and password (admin/password) as in the configuration file
minio_client = Minio(
    "127.0.0.1:9001", access_key="admin", secret_key="password", secure=False
)

# Path to download file
json_path = "data/json_tmp"
label_path = "data/label_tmp"
extractor_path = "data/extractor_tmp"

# 列出json桶中的所有对象
json_object_list = minio_client.list_objects("json")
# 列出label桶中的所有对象
label_object_list = minio_client.list_objects("label")
# 列出extractor桶中的所有对象
extractor_object_list = minio_client.list_objects("extractor")

# 将json桶中的所有对象下载到本地
for json_object in json_object_list:
    minio_client.fget_object(
        bucket_name="json", object_name=json_object.object_name, file_path=json_path
    )