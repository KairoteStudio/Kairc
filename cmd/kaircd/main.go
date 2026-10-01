package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KairoteStudio/Kairc/internal/server"
)

func main() {
	cfg := server.DefaultConfig()
	listenAddress := envString("KAIRC_LISTEN", ":6667")
	healthAddress := envString("KAIRC_HEALTH_LISTEN", ":8080")
	tlsCert := envString("KAIRC_TLS_CERT", "")
	tlsKey := envString("KAIRC_TLS_KEY", "")
	showVersion := false

	flag.StringVar(&listenAddress, "listen", listenAddress, "IRC listen address")
	flag.StringVar(&healthAddress, "health-listen", healthAddress, "HTTP health listen address; empty disables it")
	flag.StringVar(&cfg.Name, "server-name", envString("KAIRC_SERVER_NAME", cfg.Name), "public IRC server name")
	flag.StringVar(&cfg.Network, "network", envString("KAIRC_NETWORK", cfg.Network), "public IRC network name")
	flag.StringVar(&cfg.MOTD, "motd", envString("KAIRC_MOTD", cfg.MOTD), "message of the day; use \\n for multiple lines")
	flag.IntVar(&cfg.MaxClients, "max-clients", envInt("KAIRC_MAX_CLIENTS", cfg.MaxClients), "maximum concurrent client connections")
	flag.IntVar(&cfg.SendQueue, "send-queue", envInt("KAIRC_SEND_QUEUE", cfg.SendQueue), "outbound messages buffered per client")
	flag.Float64Var(&cfg.MessagesPerSecond, "rate", envFloat("KAIRC_RATE", cfg.MessagesPerSecond), "sustained inbound messages per second per client")
	flag.IntVar(&cfg.MessageBurst, "burst", envInt("KAIRC_BURST", cfg.MessageBurst), "inbound message burst per client")
	flag.DurationVar(&cfg.RegistrationTimeout, "registration-timeout", envDuration("KAIRC_REGISTRATION_TIMEOUT", cfg.RegistrationTimeout), "time allowed to register")
	flag.StringVar(&tlsCert, "tls-cert", tlsCert, "TLS certificate path")
	flag.StringVar(&tlsKey, "tls-key", tlsKey, "TLS private-key path")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()
	cfg.MOTD = strings.ReplaceAll(cfg.MOTD, `\n`, "\n")

	if showVersion {
		fmt.Println("kaircd " + server.Version)
		return
	}
	if (tlsCert == "") != (tlsKey == "") {
		fatal("both --tls-cert and --tls-key must be provided")
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	service, err := server.New(cfg, logger)
	if err != nil {
		fatal(err.Error())
	}

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		fatal("listen on " + listenAddress + ": " + err.Error())
	}
	if tlsCert != "" {
		certificate, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			_ = listener.Close()
			fatal("load TLS key pair: " + err.Error())
		}
		listener = tls.NewListener(listener, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS13,
		})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var health *http.Server
	if healthAddress != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		})
		health = &http.Server{
			Addr:              healthAddress,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			logger.Info("health endpoint listening", "address", healthAddress)
			if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("health endpoint failed", "error", err)
				stop()
			}
		}()
	}

	transport := "plain TCP"
	if tlsCert != "" {
		transport = "TLS 1.3"
	}
	logger.Info("Kairc listening", "address", listener.Addr(), "transport", transport, "network", cfg.Network)
	serveErr := service.Serve(ctx, listener)

	if health != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = health.Shutdown(shutdownCtx)
		cancel()
	}
	if serveErr != nil {
		fatal(serveErr.Error())
	}
	logger.Info("Kairc stopped")
}

func envString(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		fatal(name + " must be an integer")
	}
	return parsed
}

func envFloat(name string, fallback float64) float64 {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		fatal(name + " must be a number")
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		fatal(name + " must be a Go duration such as 30s or 2m")
	}
	return parsed
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "kaircd: "+message)
	os.Exit(1)
}
