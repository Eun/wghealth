# WireGuard Health Check

A standalone WireGuard client that connects to a single WireGuard server, performs a health check.

## Features

- ✅ No root privileges required
- ✅ No TUN/TAP or virtual network devices needed
- ✅ Userspace network stack using netstack
- ✅ Configuration via YAML file
- ✅ Automatic connection establishment
- ✅ Built-in ping test functionality
- ✅ Clean exit codes (0 for success, 1 for failure)
- ✅ Optional server mode to expose health check via HTTP

## Building

```bash
cd cmd/wghealth
go build -o wghealth
```

## Configuration

Create a YAML configuration file (see `example.config.yaml`):

## Usage

```bash
# Use default config file (wghealth.yaml)
./wghealth

# Specify custom config file
./wghealth -config=/path/to/config.yaml

# Server Mode (start a http server that does the health check on demand query /check)
./wghealth -server-mode -server-address=:8000 -server-keep-alive=false -config=/path/to/config.yaml
```

## Exit Codes (in non-server mode)
- `0`: Success - connection established and checkCGO_ successful
- `1`: Failure - connection failed or check failed

## Responses (in server mode)

### Health Check Success Response
Status Code: `200 OK`
```json
{
   "status": "health check succeeded",
   "request_id": "ea7de933-8c47-4073-be6c-d3abdf59deff",
   "duration_ms": 3587,
   "timestamp": "2024-06-10T12:34:56Z"
}
```

### Health Check Failure Response
Status Code: `503 Service Unavailable`
```json
{
   "status": "health check failed",
   "request_id": "f1dae7ac-9c3d-4357-bfaa-fa171950e3b4",
   "duration_ms": 3569,
   "timestamp": "2024-06-10T12:34:56Z"
}
```


## Systemd Service Setup

To run wghealth in server mode as a systemd service:

### 1. Create the systemd service file

Create `/etc/systemd/system/wghealth.service`:

```ini
[Unit]
Description=WireGuard Health Check Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=wghealth
Group=wghealth
WorkingDirectory=/opt/wghealth
ExecStart=/opt/wghealth/wghealth -server-mode -server-address=:8080 -server-keep-alive=false -config=/opt/wghealth/wghealth.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/wghealth
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
```

### 2. Setup steps

```bash
# Create a dedicated user for the service
sudo useradd -r -s /bin/false -d /opt/wghealth wghealth

# Create the installation directory
sudo mkdir -p /opt/wghealth

# Copy the binary and configuration
sudo cp cmd/wghealth/wghealth /opt/wghealth/
sudo cp wghealth.yaml /opt/wghealth/
sudo cp example.wireguard.conf /opt/wghealth/wireguard.conf

# Set ownership
sudo chown -R wghealth:wghealth /opt/wghealth

# Reload systemd
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable wghealth
sudo systemctl start wghealth

# Check the status
sudo systemctl status wghealth
```

### 3. View logs

```bash
# Follow logs in real-time
sudo journalctl -u wghealth -f

# View recent logs
sudo journalctl -u wghealth -n 100

# View logs with JSON formatting
sudo journalctl -u wghealth -o json-pretty
```

### 4. Service management

```bash
# Stop the service
sudo systemctl stop wghealth

# Restart the service
sudo systemctl restart wghealth

# Disable the service
sudo systemctl disable wghealth

# Reload configuration (after editing the service file)
sudo systemctl daemon-reload
sudo systemctl restart wghealth
```

### 5. Configuration options

You can customize the service by editing `/etc/systemd/system/wghealth.service`:

- **Change listening port**: Modify `-server-address=:8080` to your desired port
- **Enable keep-alive**: Change `-server-keep-alive=false` to `true` to maintain persistent WireGuard connection
- **Change config location**: Modify `-config=/opt/wghealth/wghealth.yaml` to your config path
- **Adjust restart behavior**: Modify `RestartSec=10` to change the restart delay

After any changes, run:
```bash
sudo systemctl daemon-reload
sudo systemctl restart wghealth
```
