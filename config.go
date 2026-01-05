/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package wghealth

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the WireGuard client configuration
type Config struct {
	// Client configuration
	PrivateKey string   `yaml:"private_key"`
	Address    string   `yaml:"address"`
	DNS        []string `yaml:"dns,omitempty"`
	MTU        int      `yaml:"mtu,omitempty"`

	// Server configuration
	Server ServerConfig `yaml:"server"`

	// Ping configuration
	Ping PingConfig `yaml:"ping"`
}

// ServerConfig represents the WireGuard server configuration
type ServerConfig struct {
	PublicKey           string   `yaml:"public_key"`
	Endpoint            string   `yaml:"endpoint"`
	AllowedIPs          []string `yaml:"allowed_ips"`
	PresharedKey        string   `yaml:"preshared_key,omitempty"`
	PersistentKeepalive int      `yaml:"persistent_keepalive,omitempty"`
}

// PingConfig represents the ping test configuration
type PingConfig struct {
	Target  string `yaml:"target"`
	Timeout int    `yaml:"timeout,omitempty"` // in seconds
	Count   int    `yaml:"count,omitempty"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if config.MTU == 0 {
		config.MTU = 1420
	}
	if config.Ping.Timeout == 0 {
		config.Ping.Timeout = 10
	}
	if config.Ping.Count == 0 {
		config.Ping.Count = 1
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.PrivateKey == "" {
		return fmt.Errorf("private_key is required")
	}
	if _, err := decodeKey(c.PrivateKey); err != nil {
		return fmt.Errorf("invalid private_key: %w", err)
	}

	if c.Address == "" {
		return fmt.Errorf("address is required")
	}
	if _, err := netip.ParsePrefix(c.Address); err != nil {
		// Try parsing as just an address
		if _, err := netip.ParseAddr(c.Address); err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}
	}

	if c.Server.PublicKey == "" {
		return fmt.Errorf("server.public_key is required")
	}
	if _, err := decodeKey(c.Server.PublicKey); err != nil {
		return fmt.Errorf("invalid server.public_key: %w", err)
	}

	if c.Server.Endpoint == "" {
		return fmt.Errorf("server.endpoint is required")
	}

	// resolve s.Server.Endpoint if it is a hostname
	host, port, _ := net.SplitHostPort(c.Server.Endpoint)
	if net.ParseIP(host) == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("unable to resolve server.endpoint hostname: %w", err)
		}
		c.Server.Endpoint = net.JoinHostPort(addrs[0], port)
	}

	if len(c.Server.AllowedIPs) == 0 {
		return fmt.Errorf("server.allowed_ips is required")
	}
	for _, ip := range c.Server.AllowedIPs {
		if _, err := netip.ParsePrefix(ip); err != nil {
			return fmt.Errorf("invalid allowed_ip %s: %w", ip, err)
		}
	}

	if c.Server.PresharedKey != "" {
		if _, err := decodeKey(c.Server.PresharedKey); err != nil {
			return fmt.Errorf("invalid server.preshared_key: %w", err)
		}
	}

	if c.Ping.Target == "" {
		return fmt.Errorf("ping.target is required")
	}

	return nil
}

// decodeKey decodes a base64 or hex encoded key
func decodeKey(key string) ([]byte, error) {
	key = strings.TrimSpace(key)

	// Try base64 first (standard WireGuard format)
	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	// Try hex
	if decoded, err := hex.DecodeString(key); err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	return nil, fmt.Errorf("key must be 32 bytes encoded as base64 or hex")
}

// GetClientAddress returns the parsed client address
func (c *Config) GetClientAddress() (netip.Addr, error) {
	// Try parsing as prefix first
	if prefix, err := netip.ParsePrefix(c.Address); err == nil {
		return prefix.Addr(), nil
	}
	// Try parsing as plain address
	return netip.ParseAddr(c.Address)
}

// GetDNSServers returns parsed DNS server addresses
func (c *Config) GetDNSServers() ([]netip.Addr, error) {
	if len(c.DNS) == 0 {
		return nil, nil
	}

	servers := make([]netip.Addr, 0, len(c.DNS))
	for _, dns := range c.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS address %s: %w", dns, err)
		}
		servers = append(servers, addr)
	}
	return servers, nil
}
