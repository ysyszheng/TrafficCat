# MinIO 安装和配置指南

## 下载和安装

1. 使用以下命令下载并安装 MinIO 服务器：
```bash
# 下载服务端
wget https://dl.min.io/server/minio/release/linux-amd64/minio
# 将下载所得 minio 文件拷贝到指定文件夹并赋予权限
sudo cp minio /usr/local/bin/
sudo chmod +x /usr/local/bin/minio
```

## 直接运行 MinIO

1. 创建 MinIO 存储目录：
```bash
sudo mkdir /data
```

2. 启动 MinIO，并指定存储目录和访问地址：
```bash
sudo minio server /data --console-address ":9099"
```

3. 在浏览器中访问 http://127.0.0.1:9000，系统将自动跳转到 http://127.0.0.1:9099。在用户名和密码字段中输入默认的用户名和密码（minioadmin/minioadmin），即可登录系统。

## 配置自启动服务

为了在系统重启时自动启动 MinIO 服务，可以将其配置为系统服务。

1. 创建 MinIO 配置文件：
```bash
# 创建配置文件 /etc/default/minio
sudo nano /etc/default/minio
```

2. 将以下配置信息写入文件中：
```bash
# 指定数据存储目录（注意：该目录必须存在且具有相应权限）
MINIO_VOLUMES="/data"

# 监听端口
MINIO_OPTS="--address :9099 --console-address :9099"

# 指定默认的用户名和密码，其中用户名必须大于3个字符
MINIO_ROOT_USER="admin"
MINIO_ROOT_PASSWORD="password"

# 区域值，标准格式为“国家-区域-编号”
MINIO_REGION="cn-north-1"
```
保存并退出配置文件。

3. 创建 MinIO 服务文件：
```bash
sudo nano /usr/lib/systemd/system/minio.service
```

4. 将以下配置信息写入服务文件中：
```bash
[Unit]
Description=MinIO
Documentation=https://docs.min.io
Wants=network-online.target
After=network-online.target
AssertFileIsExecutable=/usr/local/bin/minio

[Service]
WorkingDirectory=/usr/local/
ProtectProc=invisible

# 引用上一步创建的配置文件
EnvironmentFile=/etc/default/minio

ExecStartPre=/bin/bash -c "if [ -z \"${MINIO_VOLUMES}\" ]; then echo \"Variable MINIO_VOLUMES not set in /etc/default/minio\"; exit 1; fi"
ExecStart=/usr/local/bin/minio server $MINIO_OPTS $MINIO_VOLUMES

# 始终允许 systemd 重新启动该服务
Restart=always

# 指定该进程能打开的最大文件描述符数目（1M）
LimitNOFILE=1048576

# 指定该进程能创建的最大线程数
TasksMax=infinity

# 禁用超时逻辑，直到进程被停止
TimeoutStopSec=infinity
SendSIGKILL=no
SuccessExitStatus=0

[Install]
WantedBy=multi-user.target
Alias=minio.service
```
保存并退出服务文件。

5. 使服务配置生效：
```bash
# 重新加载服务配置文件
systemctl daemon-reload

# 将服务设置为开机启动
systemctl enable minio

# 启动 MinIO 服务
systemctl start minio

# 检查 MinIO 服务当前状态
systemctl status minio
```

若 MinIO 服务成功启动，可以在浏览器中访问minio控制台： http://127.0.0.1:9000 ，并使用上文配置的用户名和密码（admin/password）登录系统。