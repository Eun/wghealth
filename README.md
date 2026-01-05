# WireGuard Client

A standalone WireGuard client that connects to a single WireGuard server, performs a ping test, and exits. This client does **not** require root privileges or TUN/TAP devices as it uses a userspace network stack.

## Features

- ✅ No root privileges required
- ✅ No TUN/TAP or virtual network devices needed
- ✅ Userspace network stack using netstack
- ✅ Configuration via YAML file
- ✅ Automatic connection establishment
- ✅ Built-in ping test functionality
- ✅ Clean exit codes (0 for success, 1 for failure)

## Building

```bash
cd cmd/wgclient
go build -o wgclient
```

## Configuration

Create a YAML configuration file (see `example.config.yaml`):

```yaml
# Client settings
private_key: "YourBase64EncodedPrivateKeyHere=="
address: "10.0.0.2/24"
dns:
  - "8.8.8.8"

# Server settings
server:
  public_key: "ServerPublicKeyBase64Here=="
  endpoint: "vpn.example.com:51820"
  allowed_ips:
    - "0.0.0.0/0"
  persistent_keepalive: 25

# Ping test
ping:
  target: "8.8.8.8"
  timeout: 10
  count: 4
```

### Configuration Options

#### Client Settings
- `private_key`: Your WireGuard private key (base64 encoded, 32 bytes)
- `address`: Your VPN IP address (can be CIDR or plain IP)
- `dns`: List of DNS server IP addresses (optional)
- `mtu`: Maximum transmission unit (optional, default: 1420)

#### Server Settings
- `public_key`: Server's WireGuard public key (base64 encoded)
- `endpoint`: Server address in format `ip:port` or `hostname:port`
- `allowed_ips`: List of IP ranges to route through the VPN
- `preshared_key`: Optional pre-shared key for additional security
- `persistent_keepalive`: Send keepalive packets every N seconds (optional)

#### Ping Settings
- `target`: IP address or hostname to ping (required)
- `timeout`: Timeout in seconds (default: 10)
- `count`: Number of ping attempts (default: 1)

## Usage

```bash
# Use default config file (wgclient.yaml)
./wgclient

# Specify custom config file
./wgclient -config /path/to/config.yaml
```

## Exit Codes

- `0`: Success - connection established and ping successful
- `1`: Failure - connection failed or ping failed

## Key Generation

To generate WireGuard keys:

```bash
# Generate private key
wg genkey

# Generate public key from private key
echo "PRIVATE_KEY_HERE" | wg pubkey
```

Or use the WireGuard tools from the main package.

## Architecture

This client uses the following components from wireguard-go:

- `tun/netstack`: Userspace network stack (no kernel TUN/TAP needed)
- `device`: WireGuard protocol implementation
- `conn`: UDP connection handling

The netstack package provides a full TCP/IP stack in userspace using gVisor's netstack, which allows network operations without requiring privileged access to create virtual network interfaces.

## Example Workflow

1. Configure your client with valid WireGuard keys and server details
2. Run the client: `./wgclient -config myconfig.yaml`
3. The client will:
   - Load and validate configuration
   - Create a userspace network stack
   - Establish WireGuard connection to the server
   - Perform the configured ping test
   - Exit with code 0 (success) or 1 (failure)

## Limitations

- This is a one-off client, not a persistent daemon
- Only supports connection to a single WireGuard peer (server)
- Requires the target server to allow your public key