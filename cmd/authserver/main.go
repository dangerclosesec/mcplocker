package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bresrch/sawmill"
	"github.com/dangerclosesec/mcplocker"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	// Global flags
	debug bool
)

func main() {
	// Define global flags
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// Create a context with cancellation for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loggerOpts := []sawmill.HandlerOption{
		sawmill.WithLevel(sawmill.LevelDebug),
	}

	if os.Getenv("ENV") == "local" {
		// Custom color mappings for different key patterns
		colorMappings := map[string]string{
			"version":   sawmill.ColorBrightGreen,
			"timestamp": sawmill.ColorYellow,
			"debug":     sawmill.ColorGreen,
		}

		// Use JSON handler for Docker environments
		loggerOpts = append(loggerOpts, sawmill.WithColorsEnabled(true),
			sawmill.WithColorMappings(colorMappings))
	}

	// Initialize the logger
	logger := sawmill.New(sawmill.NewJSONHandler(
		loggerOpts...,
	))

	// Initialize the application
	logger.Info("Starting MCPLocker Auth Server", "version", mcplocker.VERSION, "debug", debug)

	r := chi.NewRouter()

	// Add your routes and middleware here
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Welcome to the MCPLocker Auth Server!"))
	})
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	// Create HTTP server with graceful shutdown
	srv := &http.Server{
		Addr: "127.0.0.1:38741",
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ErrorLog: logger.HTTPErrorLog(),
		Handler:  r,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Server started successfully", "address", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// Set up signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	// Wait for shutdown signal
	sig := <-signalCh
	logger.Info("Received shutdown signal", "signal", sig.String())
	fmt.Println("\nReceived shutdown signal. Gracefully shutting down...")

	// Create a deadline for graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
	defer shutdownCancel()

	// Gracefully shutdown the server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("Server shutdown completed")
}
