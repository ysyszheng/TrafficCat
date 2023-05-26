"""
Download all the objects in the json bucket, label bucket and extractor bucket from minio and merge the objects in each bucket into one file
"""

import os
from minio import Minio

# Path to uploaded files
json_folder = "minio/json_tmp/"
label_folder = "minio/label_tmp/"
extractor_folder = "minio/extractor_tmp/"

# Initialize the minio client object to connect to the minio service
# with the username and password (admin/password) as in the configuration file
minio_client = Minio(
    "127.0.0.1:9001", access_key="minioadmin", secret_key="minioadmin", secure=False
)


# List all objects in the json bucket
json_object_list = minio_client.list_objects("json")
# List all objects in the label bucket
label_object_list = minio_client.list_objects("label")
# List all objects in the extractor bucket
extractor_object_list = minio_client.list_objects("extractor")


# Download all the objects in the json bucket locally and merge them into one file
file_name = "minio/json_tmp/traffic-all.json"
open(file_name, "w")

# In the first line write [
with open(file_name, "a") as f:
    f.write("[")
for json_object in json_object_list:
    minio_client.fget_object(
        bucket_name="json", object_name=json_object.object_name, file_path=json_folder + json_object.object_name
    )
    with open(file_name, "a") as f:
        with open(json_folder + json_object.object_name) as f1:
            # Remove [] from the first and last lines
            f.write(f1.read()[1:-2] + ",")
    # print("download traffic file: "+json_object.object_name)
# Remove the last comma
with open(file_name, 'rb+') as f:
    f.seek(-1, os.SEEK_END)
    if f.read(1) == b',':
        f.seek(-1, os.SEEK_END)
        f.truncate()
# Write on the last line]
with open(file_name, "a") as f:
    f.write("]")

# Overwrite the original data/traffic.json with the new file
os.rename(file_name, "data/traffic.json")
# Empty the json_tmp folder
for file in os.listdir(json_folder):
    os.remove(json_folder + file)


# Download all objects in the label bucket locally and merge them into one file
file_name = "minio/label_tmp/label-all.txt"
open(file_name, "w")
for label_object in label_object_list:
    minio_client.fget_object(
        bucket_name="label", object_name=label_object.object_name, file_path=label_folder  + label_object.object_name
    )
    with open(file_name, "ab") as f:
        with open(label_folder + label_object.object_name, "rb") as f1:
            f.write(f1.read())
    # print("download label file: "+label_object.object_name)

# Overwrite the original data/label.txt with label-all.txt
os.rename(file_name, "data/label.txt")

# Emptying the label_tmp folder
for file in os.listdir(label_folder):
    os.remove(label_folder + file)


# Download all the objects in the extractor bucket locally and merge them into one file
file_name = "minio/extractor_tmp/extractor-all.txt"
open(file_name, "w")
for extractor_object in extractor_object_list:
    minio_client.fget_object(
        bucket_name="extractor",object_name=extractor_object.object_name,file_path=extractor_folder + extractor_object.object_name
    )
    with open(file_name, "ab") as f:
        with open(extractor_folder + extractor_object.object_name, "rb") as f1:
            f.write(f1.read())
    # print("download extractor file: "+extractor_object.object_name)

# Overwrite the original data/extractor.txt with extractor-all.txt
os.rename(file_name, "data/extractor.txt")
# Empty the extractor_tmp folder
for file in os.listdir(extractor_folder):
    os.remove(extractor_folder + file)



