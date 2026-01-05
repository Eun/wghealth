/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"flag"
	"fmt"
	"os"

	"wghealth"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "wghealth.yaml", "path to configuration file")
	flag.Parse()

	// Exit with proper code
	os.Exit(run(*configPath))
}

func run(configPath string) int {
	// Load configuration
	config, err := wghealth.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		return 1
	}

	// Create client
	client, err := wghealth.NewClient(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		return 1
	}
	defer client.Close()

	// Connect to WireGuard server
	fmt.Println("Connecting to WireGuard server...")
	if err := client.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to server: %v\n", err)
		return 1
	}
	fmt.Println("Connected successfully!")

	// Perform ping test
	fmt.Printf("Pinging %s...\n", config.Ping.Target)
	if err := client.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "Ping failed: %v\n", err)
		return 1
	}

	fmt.Println("\nSuccess! All tests passed.")
	return 0
}
