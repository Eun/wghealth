/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"wghealth"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "wghealth.yaml", "path to configuration file")
	serverMode := flag.Bool("server-mode", false, "run in server mode")
	serverAddress := flag.String("server-address", ":8080", "address for server mode to listen on")
	serverKeepAlive := flag.Bool("server-keep-alive", false, "keep the wireguard connetion alive")
	flag.Parse()

	// Configure zerolog for JSON output
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(os.Stdout)

	client, err := createClient(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create client")
	}

	var exitCode int
	if *serverMode {
		// Run in server mode
		log.Info().Str("address", *serverAddress).
			Bool("keep-alive", *serverKeepAlive).
			Msg("Starting server mode")
		exitCode = runServerMode(*serverAddress, *serverKeepAlive, client)
	} else {
		exitCode = runOneOfMode(client)
	}
	_ = client.Close()
	os.Exit(exitCode)
}

func createClient(configPath string) (*wghealth.Client, error) {
	log.Info().Str("config", configPath).Msg("Loading configuration")

	// Load configuration
	config, err := wghealth.LoadConfig(configPath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load configuration")
		return nil, err
	}

	// Create client
	client, err := wghealth.NewClient(config)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create client")
		return nil, err
	}
	return client, nil
}

func runOneOfMode(client *wghealth.Client) int {
	// Connect to WireGuard server
	log.Info().Msg("Connecting to WireGuard server")
	if err := client.Connect(); err != nil {
		log.Error().Err(err).Msg("Failed to connect to server")
		return 1
	}
	log.Info().Msg("Connected successfully")

	err := doHealthCheck(context.Background(), client)
	if err != nil {
		return 1
	}

	return 0
}

func runServerMode(serverAddress string, keepWireguardConnectionAlive bool, client *wghealth.Client) int {
	var mu sync.Mutex
	mux := http.NewServeMux()

	mux.HandleFunc("GET /check", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		requestStart := time.Now()
		requestID := uuid.New().String()
		logger := log.With().Str("request_id", requestID).Logger()
		r = r.WithContext(logger.WithContext(r.Context()))
		logger.Info().Msg("Received health check request")

		if !keepWireguardConnectionAlive || !client.Connected() {
			logger.Info().Msg("Connecting to WireGuard server")
			if err := client.Connect(); err != nil {
				logger.Error().Err(err).Msg("Failed to connect to server")
				writeJSONResponse(w, http.StatusServiceUnavailable, "health check failed", requestID, requestStart)
				return
			}
			logger.Info().Msg("Connected successfully")
		}

		// Perform health check
		err := doHealthCheck(r.Context(), client)
		if err != nil {
			logger.Error().Err(err).Msg("Health check failed")
			writeJSONResponse(w, http.StatusServiceUnavailable, "health check failed", requestID, requestStart)
			return
		}

		if !keepWireguardConnectionAlive {
			if err := client.Close(); err != nil {
				logger.Error().Err(err).Msg("Failed to disconnect from server")
			}
		}

		writeJSONResponse(w, http.StatusOK, "health check succeeded", requestID, requestStart)
	})

	srv := http.Server{
		Addr:              serverAddress,
		Handler:           mux,
		ReadTimeout:       time.Second * 10,
		ReadHeaderTimeout: time.Second * 2,
		WriteTimeout:      time.Second * 10,
		IdleTimeout:       time.Second * 30,
		MaxHeaderBytes:    0,
		TLSNextProto:      nil,
		ConnState:         nil,
		ErrorLog:          nil,
		BaseContext:       nil,
		ConnContext:       nil,
		HTTP2:             nil,
		Protocols:         nil,
	}

	err := srv.ListenAndServe()
	if err != nil {
		log.Error().Err(err).Msg("Failed to start HTTP server")
		return 1
	}

	return 0
}

func writeJSONResponse(w http.ResponseWriter, statusCode int, status, requestID string, requestStart time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	duration := time.Since(requestStart).Milliseconds()

	_, _ = fmt.Fprintf(w, `{"status":%q,"request_id":%q,"duration_ms":%d,"timestamp":%q}`,
		status, requestID, duration, time.Now().Format(time.RFC3339))
}

func doHealthCheck(ctx context.Context, client *wghealth.Client) error {
	// Perform health check based on configuration
	var checkErr error
	if client.Config.Ping != nil {
		log.Ctx(ctx).Info().
			Str("target", client.Config.Ping.Target).
			Int("count", client.Config.Ping.Count).
			Int("timeout", client.Config.Ping.Timeout).
			Msg("Starting ping health check")
		checkErr = client.Ping(ctx)
	} else if client.Config.HTTP != nil {
		log.Ctx(ctx).Info().
			Str("url", client.Config.HTTP.URL).
			Str("method", client.Config.HTTP.Method).
			Ints("expected_status_codes", client.Config.HTTP.ExpectedStatusCodes).
			Int("timeout", client.Config.HTTP.Timeout).
			Msg("Starting HTTP health check")
		checkErr = client.HTTPCheck(ctx)
	} else if client.Config.HTTPS != nil {
		log.Ctx(ctx).Info().
			Str("url", client.Config.HTTPS.URL).
			Str("method", client.Config.HTTPS.Method).
			Ints("expected_status_codes", client.Config.HTTPS.ExpectedStatusCodes).
			Bool("insecure_skip_verify", client.Config.HTTPS.InsecureSkipVerify).
			Int("timeout", client.Config.HTTPS.Timeout).
			Msg("Starting HTTPS health check")
		checkErr = client.HTTPSCheck(ctx)
	} else {
		log.Ctx(ctx).Error().Msg("No health check configured")
		return errors.New("no health check configured")
	}

	if checkErr != nil {
		log.Ctx(ctx).Error().Err(checkErr).Msg("Health check failed")
		return checkErr
	}

	log.Ctx(ctx).Info().Msg("Health check passed successfully")
	return nil
}
