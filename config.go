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

// CheckConfig represents a single named health check entry with its own
// WireGuard configuration, endpoint path, and health-check settings.
type CheckConfig struct {
	// Name is a unique identifier for this check.
	Name string `yaml:"name"`

	// Endpoint is the HTTP path for server mode. Defaults to /<Name> when empty.
	Endpoint string `yaml:"endpoint,omitempty"`

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

// GetEndpoint returns the HTTP path for this check. When Endpoint is not
// set in the config, the name is used as the path (prefixed with "/").
func (c *CheckConfig) GetEndpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return "/" + c.Name
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

// LoadConfig loads a list of CheckConfig entries from a YAML file.
// The file must contain a YAML sequence (list) of check objects.
func LoadConfig(path string) ([]*CheckConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var checks []*CheckConfig
	if err := yaml.Unmarshal(data, &checks); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if len(checks) == 0 {
		return nil, fmt.Errorf("config must contain at least one check")
	}

	seenNames := make(map[string]struct{})
	seenEndpoints := make(map[string]struct{})

	for i, check := range checks {
		if err := initCheckConfig(check); err != nil {
			return nil, fmt.Errorf("check[%d] %q: %w", i, check.Name, err)
		}

		if _, dup := seenNames[check.Name]; dup {
			return nil, fmt.Errorf("check[%d]: duplicate name %q", i, check.Name)
		}
		seenNames[check.Name] = struct{}{}

		ep := check.GetEndpoint()
		if _, dup := seenEndpoints[ep]; dup {
			return nil, fmt.Errorf("check[%d] %q: duplicate endpoint %q", i, check.Name, ep)
		}
		seenEndpoints[ep] = struct{}{}
	}

	return checks, nil
}

// initCheckConfig applies defaults, loads the WireGuard config file, and
// validates a single CheckConfig.
func initCheckConfig(c *CheckConfig) error {
	if c.Name == "" {
		return fmt.Errorf("name is required")
	}

	// Apply health-check defaults
	if c.Ping != nil {
		if c.Ping.Timeout == 0 {
			c.Ping.Timeout = 10
		}
		if c.Ping.Count == 0 {
			c.Ping.Count = 1
		}
	}
	if c.HTTP != nil {
		if c.HTTP.Timeout == 0 {
			c.HTTP.Timeout = 10
		}
		if c.HTTP.Method == "" {
			c.HTTP.Method = "GET"
		}
		if len(c.HTTP.ExpectedStatusCodes) == 0 {
			c.HTTP.ExpectedStatusCodes = []int{200}
		}
	}
	if c.HTTPS != nil {
		if c.HTTPS.Timeout == 0 {
			c.HTTPS.Timeout = 10
		}
		if c.HTTPS.Method == "" {
			c.HTTPS.Method = "GET"
		}
		if len(c.HTTPS.ExpectedStatusCodes) == 0 {
			c.HTTPS.ExpectedStatusCodes = []int{200}
		}
	}

	// Load and parse WireGuard configuration file
	wgConfigData, err := os.ReadFile(c.WireGuardConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read wireguard config file: %w", err)
	}

	wgConfig, err := parseWireGuardConfig(string(wgConfigData))
	if err != nil {
		return fmt.Errorf("failed to parse wireguard config: %w", err)
	}
	c.parsedWG = wgConfig

	// Set WireGuard defaults
	if c.parsedWG.MTU == 0 {
		c.parsedWG.MTU = 1420
	}

	if err := c.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return nil
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

// Validate checks if the CheckConfig is valid.
func (c *CheckConfig) Validate() error {
	if err := c.validateWireGuard(); err != nil {
		return err
	}
	if err := c.validateHealthChecks(); err != nil {
		return err
	}
	return nil
}

// validateWireGuard validates the WireGuard-specific fields and resolves the endpoint.
func (c *CheckConfig) validateWireGuard() error {
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
func (c *CheckConfig) resolveEndpoint() error {
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
func (c *CheckConfig) validateHealthChecks() error {
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
func (c *CheckConfig) GetClientAddress() (netip.Addr, error) {
	// Try parsing as prefix first
	if prefix, err := netip.ParsePrefix(c.parsedWG.Address); err == nil {
		return prefix.Addr(), nil
	}
	// Try parsing as plain address
	return netip.ParseAddr(c.parsedWG.Address)
}

// GetDNSServers returns parsed DNS server addresses.
func (c *CheckConfig) GetDNSServers() ([]netip.Addr, error) {
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
func (c *CheckConfig) GetWireGuardConfig() *WireGuardConfig {
	return c.parsedWG
}
