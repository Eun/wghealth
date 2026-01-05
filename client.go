/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package wghealth

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Client represents a WireGuard client instance
type Client struct {
	config *Config
	device *device.Device
	tun    *netstack.Net
}

// NewClient creates a new WireGuard client from configuration
func NewClient(config *Config) (*Client, error) {
	return &Client{
		config: config,
	}, nil
}

// Connect establishes the WireGuard connection
func (c *Client) Connect() error {
	// Parse client address
	clientAddr, err := c.config.GetClientAddress()
	if err != nil {
		return fmt.Errorf("failed to parse client address: %w", err)
	}

	// Parse DNS servers
	dnsServers, err := c.config.GetDNSServers()
	if err != nil {
		return fmt.Errorf("failed to parse DNS servers: %w", err)
	}

	// Create netstack TUN device (userspace network stack, no root required)
	wgConfig := c.config.GetWireGuardConfig()
	tunDevice, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{clientAddr},
		dnsServers,
		wgConfig.MTU,
	)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %w", err)
	}
	c.tun = tnet

	// Create WireGuard device
	logger := device.NewLogger(device.LogLevelSilent, "")
	c.device = device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	// Configure the device using IPC format
	ipcConfig, err := c.buildIPCConfig()
	if err != nil {
		return fmt.Errorf("failed to build IPC config: %w", err)
	}

	if err := c.device.IpcSet(ipcConfig); err != nil {
		return fmt.Errorf("failed to configure device: %w", err)
	}

	// Bring the device up
	if err := c.device.Up(); err != nil {
		return fmt.Errorf("failed to bring device up: %w", err)
	}

	// Wait a moment for the connection to establish
	time.Sleep(500 * time.Millisecond)

	return nil
}

// buildIPCConfig creates the IPC configuration string for the WireGuard device
func (c *Client) buildIPCConfig() (string, error) {
	var config strings.Builder
	wgConfig := c.config.GetWireGuardConfig()

	// Set private key (must be hex-encoded for IPC)
	privateKeyHex, err := keyToHex(wgConfig.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode private_key: %w", err)
	}
	config.WriteString(fmt.Sprintf("private_key=%s\n", privateKeyHex))

	// Configure peer (server)
	publicKeyHex, err := keyToHex(wgConfig.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode public_key: %w", err)
	}
	config.WriteString(fmt.Sprintf("public_key=%s\n", publicKeyHex))
	config.WriteString(fmt.Sprintf("endpoint=%s\n", c.config.resolvedEndpoint))

	// Set preshared key if provided
	if wgConfig.PresharedKey != "" {
		presharedKeyHex, err := keyToHex(wgConfig.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("failed to encode preshared_key: %w", err)
		}
		config.WriteString(fmt.Sprintf("preshared_key=%s\n", presharedKeyHex))
	}

	// Set persistent keepalive if provided
	if wgConfig.PersistentKeepalive > 0 {
		config.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", wgConfig.PersistentKeepalive))
	}

	// Set allowed IPs
	for _, allowedIP := range wgConfig.AllowedIPs {
		config.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP))
	}

	return config.String(), nil
}

// keyToHex converts a key (base64 or hex) to hex format for IPC
func keyToHex(key string) (string, error) {
	// Decode the key (handles both base64 and hex)
	decoded, err := decodeKey(key)
	if err != nil {
		return "", err
	}
	// Return as hex
	return hex.EncodeToString(decoded), nil
}

// Ping sends ICMP ping packets to the target and returns success/failure
func (c *Client) Ping() error {
	if c.tun == nil {
		return fmt.Errorf("client not connected")
	}

	target := c.config.Ping.Target
	timeout := time.Duration(c.config.Ping.Timeout) * time.Second
	count := c.config.Ping.Count

	// Determine if target is IPv4 or IPv6
	targetAddr, err := c.resolveTarget(target)
	if err != nil {
		return fmt.Errorf("failed to resolve target: %w", err)
	}

	isIPv6 := targetAddr.Is6()
	network := "ping4"
	var icmpType icmp.Type = ipv4.ICMPTypeEcho
	protoNum := 1
	if isIPv6 {
		network = "ping6"
		icmpType = ipv6.ICMPTypeEchoRequest
		protoNum = 58
	}

	// Create ping socket
	socket, err := c.tun.Dial(network, targetAddr.String())
	if err != nil {
		return fmt.Errorf("failed to create ping socket: %w", err)
	}
	defer socket.Close()

	var lastErr error
	successCount := 0

	for i := 0; i < count; i++ {
		// Create ping request
		requestPing := icmp.Echo{
			ID:   rand.Intn(1 << 16),
			Seq:  i,
			Data: []byte(fmt.Sprintf("wghealth ping %d", i)),
		}

		icmpBytes, err := (&icmp.Message{
			Type: icmpType,
			Code: 0,
			Body: &requestPing,
		}).Marshal(nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to marshal ICMP message: %w", err)
			continue
		}

		// Set timeout
		deadline := time.Now().Add(timeout)
		if err := socket.SetDeadline(deadline); err != nil {
			lastErr = fmt.Errorf("failed to set deadline: %w", err)
			continue
		}

		// Send ping
		start := time.Now()
		_, err = socket.Write(icmpBytes)
		if err != nil {
			lastErr = fmt.Errorf("failed to send ping: %w", err)
			continue
		}

		// Read response
		responseBuffer := make([]byte, 1500)
		n, err := socket.Read(responseBuffer)
		if err != nil {
			lastErr = fmt.Errorf("failed to receive ping response: %w", err)
			continue
		}
		latency := time.Since(start)

		// Parse response
		replyPacket, err := icmp.ParseMessage(protoNum, responseBuffer[:n])
		if err != nil {
			lastErr = fmt.Errorf("failed to parse ICMP response: %w", err)
			continue
		}

		replyPing, ok := replyPacket.Body.(*icmp.Echo)
		if !ok {
			lastErr = fmt.Errorf("invalid reply type: %v", replyPacket)
			continue
		}

		if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
			lastErr = fmt.Errorf("ping reply mismatch (seq=%d, expected=%d)", replyPing.Seq, requestPing.Seq)
			continue
		}

		// Success
		fmt.Printf("Reply from %s: seq=%d time=%v\n", targetAddr, i, latency)
		successCount++

		// Wait before next ping (if not the last one)
		if i < count-1 {
			time.Sleep(1 * time.Second)
		}
	}

	if successCount == 0 {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("all pings failed")
	}

	fmt.Printf("\nPing statistics: %d/%d packets successful\n", successCount, count)
	return nil
}

// resolveTarget resolves the target hostname or IP address
func (c *Client) resolveTarget(target string) (netip.Addr, error) {
	// Try parsing as IP address first
	if addr, err := netip.ParseAddr(target); err == nil {
		return addr, nil
	}

	// Resolve hostname using the netstack DNS resolver
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := c.tun.LookupContextHost(ctx, target)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("DNS lookup failed: %w", err)
	}

	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses found for %s", target)
	}

	// Return the first address
	addr, err := netip.ParseAddr(addrs[0])
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to parse resolved address: %w", err)
	}

	return addr, nil
}

// Close closes the WireGuard connection
func (c *Client) Close() error {
	if c.device != nil {
		c.device.Close()
		// Wait for device to close
		<-c.device.Wait()
	}
	return nil
}
