"""
Uploading and downloading files using python
The minio library needs to be pre-installed: pip install minio
"""

from minio import Minio

# Initialize the minio client object to connect to the minio service
# with the username and password (admin/password) as in the configuration file
minio_client = Minio(
    "127.0.0.1:9001", access_key="minioadmin", secret_key="minioadmin", secure=False
)

# upload
# Path to uploaded files
uploadpath = "test.txt"
# Upload a file to the test bucket in minio
# the file name stored in minio is object4 and the path of the uploaded file is path
minio_client.fput_object(bucket_name="test", object_name="object4", file_path=uploadpath)

# download
# Path to download file
downloadpath = "test'.txt"
# Download the file from the test bucket in minio
# the file name stored in minio is object4 and the path to the downloaded file is path
minio_client.fget_object(bucket_name="test", object_name="object4", file_path=downloadpath)
