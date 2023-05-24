# Deploying MinIO on Ubuntu

## Downloading and Installing

1. Use the following command to download and install the MinIO server:
```bash
# Download the server
wget https://dl.min.io/server/minio/release/linux-amd64/minio
# Copy the downloaded minio file to the specified folder and give it executable permissions
sudo cp minio /usr/local/bin/
sudo chmod +x /usr/local/bin/minio
```

## Running MinIO Directly

1. Create the MinIO storage directory:
```bash
sudo mkdir /data
```

2. Start MinIO, specifying the storage directory and access address:
```bash
sudo minio server /data --console-address ":9099"
```

3. Access http://127.0.0.1:9000 in your browser. The system will automatically redirect to http://127.0.0.1:9099. Enter the default username and password (minioadmin/minioadmin) in the username and password fields to log in to the system.

## Configuring Auto-Start Service

To automatically start the MinIO service upon system reboot, you can configure it as a system service.

1. Create the MinIO configuration file:
```bash
# Create the configuration file /etc/default/minio
sudo nano /etc/default/minio
```

2. Write the following configuration information into the file:
```bash
# Specify the data storage directory (Note: The directory must exist and have appropriate permissions)
MINIO_VOLUMES="/data"

# Listening port
MINIO_OPTS="--address :9099 --console-address :9099"

# Specify the default username and password, where the username must be longer than 3 characters
MINIO_ROOT_USER="admin"
MINIO_ROOT_PASSWORD="password"

# Region value, standard format is "country-region-code"
MINIO_REGION="cn-north-1"
```
Save and exit the configuration file.

3. Create the MinIO service file:
```bash
sudo nano /usr/lib/systemd/system/minio.service
```

4. Write the following configuration information into the service file:
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

# Reference the configuration file created in the previous step
EnvironmentFile=/etc/default/minio

ExecStartPre=/bin/bash -c "if [ -z \"${MINIO_VOLUMES}\" ]; then echo \"Variable MINIO_VOLUMES not set in /etc/default/minio\"; exit 1; fi"
ExecStart=/usr/local/bin/minio server $MINIO_OPTS $MINIO_VOLUMES

# Always allow systemd to restart the service
Restart=always

# Specify the maximum number of file descriptors the process can open (1M)
LimitNOFILE=1048576

# Specify the maximum number of threads the process can create
TasksMax=infinity

# Disable timeout logic until the process is stopped
TimeoutStopSec=infinity
SendSIGKILL=no
SuccessExitStatus=0

[Install]
WantedBy=multi-user.target
Alias=minio.service
```
Save and exit the service file.

5. Make the service configuration take effect:
```bash
# Reload the service configuration file
systemctl daemon-reload

# Set the service to start on boot
systemctl enable minio

# Start the MinIO service
systemctl start minio

# Check the current status of the MinIO service
systemctl status minio
```

If the MinIO service starts successfully, you

 can access the MinIO console in your browser at http://127.0.0.1:9000 and log in to the system using the username and password configured earlier (admin/password).