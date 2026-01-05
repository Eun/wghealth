/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"flag"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"wghealth"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "wghealth.yaml", "path to configuration file")
	flag.Parse()

	// Configure zerolog for JSON output
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(os.Stdout)

	// Exit with proper code
	os.Exit(run(*configPath))
}

func run(configPath string) int {
	log.Info().Str("config", configPath).Msg("Loading configuration")
	
	// Load configuration
	config, err := wghealth.LoadConfig(configPath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load configuration")
		return 1
	}

	// Create client
	client, err := wghealth.NewClient(config)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create client")
		return 1
	}
	defer client.Close()

	// Connect to WireGuard server
	log.Info().Msg("Connecting to WireGuard server")
	if err := client.Connect(); err != nil {
		log.Error().Err(err).Msg("Failed to connect to server")
		return 1
	}
	log.Info().Msg("Connected successfully")

	// Perform health check based on configuration
	var checkErr error
	if config.Ping != nil {
		log.Info().
			Str("target", config.Ping.Target).
			Int("count", config.Ping.Count).
			Int("timeout", config.Ping.Timeout).
			Msg("Starting ping health check")
		checkErr = client.Ping()
	} else if config.HTTP != nil {
		log.Info().
			Str("url", config.HTTP.URL).
			Str("method", config.HTTP.Method).
			Ints("expected_status_codes", config.HTTP.ExpectedStatusCodes).
			Int("timeout", config.HTTP.Timeout).
			Msg("Starting HTTP health check")
		checkErr = client.HTTPCheck()
	} else if config.HTTPS != nil {
		log.Info().
			Str("url", config.HTTPS.URL).
			Str("method", config.HTTPS.Method).
			Ints("expected_status_codes", config.HTTPS.ExpectedStatusCodes).
			Bool("insecure_skip_verify", config.HTTPS.InsecureSkipVerify).
			Int("timeout", config.HTTPS.Timeout).
			Msg("Starting HTTPS health check")
		checkErr = client.HTTPSCheck()
	} else {
		log.Error().Msg("No health check configured")
		return 1
	}

	if checkErr != nil {
		log.Error().Err(checkErr).Msg("Health check failed")
		return 1
	}

	log.Info().Msg("Health check passed successfully")
	return 0
}
