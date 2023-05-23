"""
使用python上传和下载文件
需要预先安装minio库：pip install minio
"""

from minio import Minio

# 初始化minio客户端对象，连接minio服务，用户名和密码（admin/password）为配置文件中的内容
minio_client = Minio(
    "127.0.0.1:9000", access_key="admin", secret_key="password", secure=False
)

# upload
# 上传文件的路径
uploadpath = "test.txt"
# 向minio中的test桶中上传文件，minio中存储的文件名为object4，上传的文件路径为path
minio_client.fput_object(bucket_name="test", object_name="object4", file_path=uploadpath)

# download
# 下载文件的路径
downloadpath = "test'.txt"
# 从minio中的test桶中下载文件，minio中存储的文件名为object4，下载的文件路径为path
minio_client.fget_object(bucket_name="test", object_name="object4", file_path=downloadpath)
