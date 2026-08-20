/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package wghealth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	// Path to WireGuard configuration file
	WireGuardConfigPath string `yaml:"wireguard_config_path"`

	// Health check configuration (only one should be specified)
	Ping  *PingConfig  `yaml:"ping,omitempty"`
	HTTP  *HTTPConfig  `yaml:"http,omitempty"`
	HTTPS *HTTPSConfig `yaml:"https,omitempty"`

	// Parsed WireGuard settings (internal use)
	parsedWG *WireGuardConfig

	resolvedEndpoint string
}

// WireGuardConfig represents parsed WireGuard settings.
type WireGuardConfig struct {
	PrivateKey          string
	Address             string
	DNS                 []string
	MTU                 int
	PublicKey           string
	AllowedIPs          []string
	Endpoint            string
	PresharedKey        string
	PersistentKeepalive int
}

// PingConfig represents the ping test configuration.
type PingConfig struct {
	Target  string `yaml:"target"`
	Timeout int    `yaml:"timeout,omitempty"` // in seconds
	Count   int    `yaml:"count,omitempty"`
}

// HTTPConfig represents the HTTP health check configuration.
type HTTPConfig struct {
	URL                 string `yaml:"url"`
	Timeout             int    `yaml:"timeout,omitempty"`               // in seconds
	Method              string `yaml:"method,omitempty"`                // default: GET
	ExpectedStatusCodes []int  `yaml:"expected_status_codes,omitempty"` // expected HTTP status codes (default: [200])
}

// HTTPSConfig represents the HTTPS health check configuration.
type HTTPSConfig struct {
	URL                 string `yaml:"url"`
	Timeout             int    `yaml:"timeout,omitempty"`               // in seconds
	Method              string `yaml:"method,omitempty"`                // default: GET
	InsecureSkipVerify  bool   `yaml:"insecure_skip_verify,omitempty"`  // skip certificate verification
	ExpectedStatusCodes []int  `yaml:"expected_status_codes,omitempty"` // expected HTTP status codes (default: [200])
}

// LoadConfig loads configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set health check defaults
	if config.Ping != nil {
		if config.Ping.Timeout == 0 {
			config.Ping.Timeout = 10
		}
		if config.Ping.Count == 0 {
			config.Ping.Count = 1
		}
	}
	if config.HTTP != nil {
		if config.HTTP.Timeout == 0 {
			config.HTTP.Timeout = 10
		}
		if config.HTTP.Method == "" {
			config.HTTP.Method = "GET"
		}
		if len(config.HTTP.ExpectedStatusCodes) == 0 {
			config.HTTP.ExpectedStatusCodes = []int{200}
		}
	}
	if config.HTTPS != nil {
		if config.HTTPS.Timeout == 0 {
			config.HTTPS.Timeout = 10
		}
		if config.HTTPS.Method == "" {
			config.HTTPS.Method = "GET"
		}
		if len(config.HTTPS.ExpectedStatusCodes) == 0 {
			config.HTTPS.ExpectedStatusCodes = []int{200}
		}
	}

	// Load and parse WireGuard configuration file
	wgConfigData, err := os.ReadFile(config.WireGuardConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read wireguard config file: %w", err)
	}

	wgConfig, err := parseWireGuardConfig(string(wgConfigData))
	if err != nil {
		return nil, fmt.Errorf("failed to parse wireguard config: %w", err)
	}
	config.parsedWG = wgConfig

	// Set WireGuard defaults
	if config.parsedWG.MTU == 0 {
		config.parsedWG.MTU = 1420
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// parseWireGuardConfig parses the WireGuard INI-style configuration.
func parseWireGuardConfig(configStr string) (*WireGuardConfig, error) {
	config := &WireGuardConfig{}
	scanner := bufio.NewScanner(strings.NewReader(configStr))

	var currentSection string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// Parse key = value pairs
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "interface":
			switch strings.ToLower(key) {
			case "privatekey":
				config.PrivateKey = value
			case "address":
				config.Address = value
			case "dns":
				config.DNS = strings.Split(value, ",")
				for i := range config.DNS {
					config.DNS[i] = strings.TrimSpace(config.DNS[i])
				}
			case "mtu":
				_, _ = fmt.Sscanf(value, "%d", &config.MTU)
			}
		case "peer":
			switch strings.ToLower(key) {
			case "publickey":
				config.PublicKey = value
			case "allowedips":
				config.AllowedIPs = strings.Split(value, ",")
				for i := range config.AllowedIPs {
					config.AllowedIPs[i] = strings.TrimSpace(config.AllowedIPs[i])
				}
			case "endpoint":
				config.Endpoint = value
			case "presharedkey":
				config.PresharedKey = value
			case "persistentkeepalive":
				_, _ = fmt.Sscanf(value, "%d", &config.PersistentKeepalive)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if err := c.validateWireGuard(); err != nil {
		return err
	}
	if err := c.validateHealthChecks(); err != nil {
		return err
	}
	return nil
}

// validateWireGuard validates the WireGuard-specific fields and resolves the endpoint.
func (c *Config) validateWireGuard() error {
	if c.parsedWG.PrivateKey == "" {
		return fmt.Errorf("private_key is required")
	}
	if _, err := decodeKey(c.parsedWG.PrivateKey); err != nil {
		return fmt.Errorf("invalid private_key: %w", err)
	}

	if c.parsedWG.Address == "" {
		return fmt.Errorf("address is required")
	}
	if _, err := netip.ParsePrefix(c.parsedWG.Address); err != nil {
		// Try parsing as just an address
		if _, err := netip.ParseAddr(c.parsedWG.Address); err != nil {
			return fmt.Errorf("invalid address: %w", err)
		}
	}

	if c.parsedWG.PublicKey == "" {
		return fmt.Errorf("server.public_key is required")
	}
	if _, err := decodeKey(c.parsedWG.PublicKey); err != nil {
		return fmt.Errorf("invalid server.public_key: %w", err)
	}

	if c.parsedWG.Endpoint == "" {
		return fmt.Errorf("server.endpoint is required")
	}
	if err := c.resolveEndpoint(); err != nil {
		return err
	}

	if len(c.parsedWG.AllowedIPs) == 0 {
		return fmt.Errorf("server.allowed_ips is required")
	}
	for _, ip := range c.parsedWG.AllowedIPs {
		if _, err := netip.ParsePrefix(ip); err != nil {
			return fmt.Errorf("invalid allowed_ip %s: %w", ip, err)
		}
	}

	if c.parsedWG.PresharedKey != "" {
		if _, err := decodeKey(c.parsedWG.PresharedKey); err != nil {
			return fmt.Errorf("invalid server.preshared_key: %w", err)
		}
	}
	return nil
}

// resolveEndpoint resolves the endpoint hostname to an IP address if needed.
func (c *Config) resolveEndpoint() error {
	c.resolvedEndpoint = c.parsedWG.Endpoint
	host, port, _ := net.SplitHostPort(c.resolvedEndpoint)
	if net.ParseIP(host) == nil {
		var resolver net.Resolver
		addrs, err := resolver.LookupHost(context.Background(), host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("unable to resolve server.endpoint hostname: %w", err)
		}
		c.resolvedEndpoint = net.JoinHostPort(addrs[0], port)
	}
	return nil
}

// validateHealthChecks validates that exactly one health check is configured.
func (c *Config) validateHealthChecks() error {
	checksConfigured := 0
	if c.Ping != nil {
		checksConfigured++
		if c.Ping.Target == "" {
			return fmt.Errorf("ping.target is required")
		}
	}
	if c.HTTP != nil {
		checksConfigured++
		if c.HTTP.URL == "" {
			return fmt.Errorf("http.url is required")
		}
	}
	if c.HTTPS != nil {
		checksConfigured++
		if c.HTTPS.URL == "" {
			return fmt.Errorf("https.url is required")
		}
	}
	if checksConfigured == 0 {
		return fmt.Errorf("at least one health check (ping, http, or https) must be configured")
	}
	if checksConfigured > 1 {
		return fmt.Errorf("only one health check type can be configured at a time")
	}
	return nil
}

// decodeKey decodes a base64 or hex encoded key.
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

// GetClientAddress returns the parsed client address.
func (c *Config) GetClientAddress() (netip.Addr, error) {
	// Try parsing as prefix first
	if prefix, err := netip.ParsePrefix(c.parsedWG.Address); err == nil {
		return prefix.Addr(), nil
	}
	// Try parsing as plain address
	return netip.ParseAddr(c.parsedWG.Address)
}

// GetDNSServers returns parsed DNS server addresses.
func (c *Config) GetDNSServers() ([]netip.Addr, error) {
	if len(c.parsedWG.DNS) == 0 {
		return nil, nil
	}

	servers := make([]netip.Addr, 0, len(c.parsedWG.DNS))
	for _, dns := range c.parsedWG.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS address %s: %w", dns, err)
		}
		servers = append(servers, addr)
	}
	return servers, nil
}

// GetWireGuardConfig returns the parsed WireGuard configuration.
func (c *Config) GetWireGuardConfig() *WireGuardConfig {
	return c.parsedWG
}
