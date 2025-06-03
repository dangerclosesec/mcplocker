package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bresrch/sawmill"
	"github.com/dangerclosesec/mcplocker"
	logcfg "github.com/dangerclosesec/mcplocker/internal/logger"
	mcps "github.com/dangerclosesec/mcplocker/internal/mcps"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	_ "github.com/dangerclosesec/mcplocker/mcps/google/calendar" // Register Google Calendar MCP
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
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize the logger - write to stderr to avoid interfering with MCP protocol
	opts := append(logcfg.WithOptionsForEnvironment(logcfg.GetEnv("ENV", "production"), debug), sawmill.WithStderr())
	logger := sawmill.New(sawmill.NewJSONHandler(opts...))

	// Set up signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		logger.Info("Received shutdown signal", "signal", sig.String())
		fmt.Fprintln(os.Stderr, "\nReceived shutdown signal. Gracefully shutting down...")
		cancel()
	}()

	// Create a new MCP server
	s := server.NewMCPServer(
		"MCP Locker",
		mcplocker.VERSION,
		server.WithToolCapabilities(true),
	)

	for _, mcp := range mcps.ListMCPs() {
		s.AddTool(mcp.Tool, mcp.Handler)
	}

	// Start the stdio server
	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
	}
}

func helloHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := request.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Hello, %s!", name)), nil
}
