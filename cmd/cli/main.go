package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bresrch/sawmill"
	"github.com/dangerclosesec/mcplocker"
	"github.com/dangerclosesec/mcplocker/internal/auth"
	"github.com/dangerclosesec/mcplocker/internal/config"
	logcfg "github.com/dangerclosesec/mcplocker/internal/logger"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var (
	// Global flags
	debug bool
)

func main() {
	// Define global flags
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	// Initialize the logger - write to stderr to avoid interfering with MCP protocol
	opts := append(logcfg.WithOptionsForEnvironment(logcfg.GetEnv("ENV", "production"), debug), sawmill.WithStderr())
	logger := sawmill.New(sawmill.NewJSONHandler(opts...))

	// Check if we should run as MCP server or show help
	cfg, err := config.Load()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Parse subcommands
	args := flag.Args()
	if len(args) == 0 {
		// If no token is configured and this looks like an interactive terminal, show help
		if !cfg.HasValidToken() && isInteractiveTTY() {
			fmt.Fprintf(os.Stderr, "MCPLocker CLI is not configured for authentication.\n\n")
			fmt.Fprintf(os.Stderr, "To get started:\n")
			fmt.Fprintf(os.Stderr, "1. Set your auth server URL: mcplocker config set-server <URL>\n")
			fmt.Fprintf(os.Stderr, "2. Authenticate: mcplocker auth\n")
			fmt.Fprintf(os.Stderr, "3. Check status: mcplocker status\n\n")
			fmt.Fprintf(os.Stderr, "Run 'mcplocker help' for more commands.\n\n")
			fmt.Fprintf(os.Stderr, "Note: To run as an MCP server (for use with MCP clients), ensure\n")
			fmt.Fprintf(os.Stderr, "authentication is configured first, then run without arguments.\n")
			os.Exit(1)
		}

		// Default behavior: run as MCP server (when auth is configured or not interactive)
		runMCPServer(logger)
		return
	}

	switch args[0] {
	case "auth":
		handleAuthCommand(args[1:], logger, cfg)
	case "config":
		handleConfigCommand(args[1:], logger, cfg)
	case "status":
		handleStatusCommand(args[1:], logger, cfg)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `MCPLocker CLI - Secure MCP Tool Proxy

Usage:
  mcplocker [command]

Available Commands:
  auth     Configure authentication with MCPLocker server
  config   Manage configuration settings
  status   Show authentication and connection status
  help     Show this help message

Flags:
  --debug  Enable debug logging

When run without a command, mcplocker operates as an MCP server.

Examples:
  mcplocker auth                    # Configure authentication
  mcplocker config set-server URL  # Set auth server URL
  mcplocker status                  # Show current status
  mcplocker                         # Run as MCP server

`)
}

func runMCPServer(logger sawmill.Logger) {
	// Create a context with cancellation for graceful shutdown
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Create auth client
	authClient := auth.NewClient(cfg)

	// Validate connection to auth server if token is configured
	if cfg.HasValidToken() {
		ctx, validateCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := authClient.Ping(ctx); err != nil {
			logger.Warn("Failed to connect to auth server", "error", err, "url", cfg.AuthServerURL)
			fmt.Fprintf(os.Stderr, "❌ Cannot connect to auth server at %s\n", cfg.AuthServerURL)
			fmt.Fprintf(os.Stderr, "   Error: %v\n", err)
			fmt.Fprintf(os.Stderr, "   Try running 'mcplocker auth' to re-authenticate.\n")
		} else {
			logger.Info("Connected to auth server", "url", cfg.AuthServerURL)
			fmt.Fprintf(os.Stderr, "✅ Connected to MCPLocker server at %s\n", cfg.AuthServerURL)
		}
		validateCancel()
	} else {
		logger.Warn("No auth token configured, running in local mode")
		fmt.Fprintf(os.Stderr, "❌ No auth token configured. MCP tools will not work.\n")
		fmt.Fprintf(os.Stderr, "   Run 'mcplocker auth' to configure authentication.\n")
	}

	// Set up signal handling
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalCh
		logger.Info("Received shutdown signal", "signal", sig.String())
		fmt.Fprintln(os.Stderr, "\nReceived shutdown signal. Gracefully shutting down...")
		cancel()
	}()

	// Create a new MCP server with tool capabilities enabled for notifications
	s := server.NewMCPServer(
		"MCP Locker",
		mcplocker.VERSION,
		server.WithToolCapabilities(true), // Enable tool change notifications
	)

	// Fetch available tools from authserver on startup if authenticated
	if cfg.HasValidToken() {
		fmt.Fprintf(os.Stderr, "Syncing available tools from auth server...\n")
		if err := syncToolsFromAuthServer(s, authClient, cfg, logger); err != nil {
			logger.Warn("Failed to sync tools from auth server on startup", "error", err)
			fmt.Fprintf(os.Stderr, "Warning: Failed to sync tools from auth server: %v\n", err)
		}
	}

	// Add tools based on configuration (including any newly synced tools)
	for _, toolConfig := range cfg.GetEnabledTools() {
		addProxyTool(s, toolConfig, authClient, logger)
	}

	// Start polling for tool updates if authenticated
	if cfg.HasValidToken() {
		go startToolPolling(s, authClient, cfg, logger, cancel)
		go startToolChangeListener(s, authClient, cfg, logger, cancel)
	}

	// Start the stdio server
	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
	}
}

// addProxyTool adds a proxy tool that forwards requests to the auth server
func addProxyTool(s *server.MCPServer, toolConfig config.ToolConfig, authClient *auth.Client, logger sawmill.Logger) {
	// Create tool schema based on the provider/service
	tool := createToolSchema(toolConfig)

	// Create handler that proxies requests to auth server
	handler := func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Extract parameters from the request
		parameters := make(map[string]interface{})
		if request.Params.Arguments != nil {
			if args, ok := request.Params.Arguments.(map[string]interface{}); ok {
				for key, value := range args {
					parameters[key] = value
				}
			}
		}

		logger.Info("Proxying tool call", "tool", toolConfig.Name, "provider", toolConfig.Provider, "service", toolConfig.Service)
		fmt.Fprintf(os.Stderr, "DEBUG CLI: Proxying tool call %s with parameters: %+v\n", toolConfig.Name, parameters)

		// Forward request to auth server
		resp, err := authClient.ProxyToolCall(ctx, toolConfig.Name, parameters)
		if err != nil {
			logger.Error("Failed to proxy tool call", "error", err, "tool", toolConfig.Name)
			fmt.Fprintf(os.Stderr, "DEBUG CLI: Proxy error: %v\n", err)
			
			// Check if this is an auth error and provide helpful message
			if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "Invalid or expired token") || strings.Contains(err.Error(), "Authorization header required") {
				return mcp.NewToolResultError("Authentication failed. Please run 'mcplocker auth' to re-authenticate."), nil
			}
			
			return mcp.NewToolResultError(fmt.Sprintf("Proxy error: %v", err)), nil
		}

		if !resp.Success {
			logger.Error("Tool call failed on auth server", "error", resp.Error, "tool", toolConfig.Name)
			fmt.Fprintf(os.Stderr, "DEBUG CLI: Tool call failed: %s\n", resp.Error)
			return mcp.NewToolResultError(resp.Error), nil
		}

		// Convert result to string for MCP response
		resultStr := fmt.Sprintf("%v", resp.Result)
		logger.Info("Tool call completed successfully", "tool", toolConfig.Name)
		fmt.Fprintf(os.Stderr, "DEBUG CLI: Tool call successful, result: %s\n", resultStr)
		return mcp.NewToolResultText(resultStr), nil
	}

	s.AddTool(tool, handler)
}

// createToolSchema creates an MCP tool schema based on the tool configuration
func createToolSchema(toolConfig config.ToolConfig) mcp.Tool {
	description := fmt.Sprintf("%s %s tool (proxied through MCPLocker)", toolConfig.Provider, toolConfig.Service)

	// Handle specific tool types based on name patterns
	switch {
	// Gmail tools
	case strings.Contains(toolConfig.Name, "gmail_send"):
		return createGmailSendTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "gmail_read"):
		return createGmailReadTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "gmail"):
		return createGoogleGmailTool(toolConfig.Name, description)

	// Calendar tools
	case strings.Contains(toolConfig.Name, "calendar_create"):
		return createCalendarCreateTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "calendar_update"):
		return createCalendarUpdateTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "calendar_get"):
		return createCalendarGetTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "calendar"):
		return createGoogleCalendarTool(toolConfig.Name, description)

	// Drive tools
	case strings.Contains(toolConfig.Name, "drive_list"):
		return createDriveListTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "drive_create"):
		return createDriveCreateTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "drive"):
		return createGoogleDriveTool(toolConfig.Name, description)

	// GitHub tools
	case strings.Contains(toolConfig.Name, "github_repo") || strings.Contains(toolConfig.Name, "repos"):
		return createGitHubRepoTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "github_issue") || strings.Contains(toolConfig.Name, "issues"):
		return createGitHubIssueTool(toolConfig.Name, description)
	case strings.Contains(toolConfig.Name, "github"):
		return createGitHubTool(toolConfig.Name, description)

	// Legacy provider/service based routing
	default:
		switch toolConfig.Provider {
		case "google":
			switch toolConfig.Service {
			case "calendar":
				return createGoogleCalendarTool(toolConfig.Name, description)
			case "gmail":
				return createGoogleGmailTool(toolConfig.Name, description)
			case "drive":
				return createGoogleDriveTool(toolConfig.Name, description)
			}
		case "slack":
			return createSlackTool(toolConfig.Name, description)
		case "github":
			switch toolConfig.Service {
			case "repos":
				return createGitHubRepoTool(toolConfig.Name, description)
			case "issues":
				return createGitHubIssueTool(toolConfig.Name, description)
			default:
				return createGitHubTool(toolConfig.Name, description)
			}
		}
	}

	// Default generic tool
	return mcp.NewTool(toolConfig.Name,
		mcp.WithDescription(description),
		mcp.WithString("input",
			mcp.Description("Input for the tool"),
		),
	)
}

// Tool schema creators for different providers/services
func createGoogleCalendarTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("event_name",
			mcp.Required(),
			mcp.Description("Name of the calendar event"),
		),
		mcp.WithString("event_date",
			mcp.Required(),
			mcp.Description("Date of the event in YYYY-MM-DD format"),
		),
		mcp.WithString("event_time",
			mcp.Description("Time of the event in HH:MM format"),
		),
		mcp.WithString("description",
			mcp.Description("Description of the event"),
		),
	)
}

func createGoogleGmailTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("to",
			mcp.Required(),
			mcp.Description("Recipient email address"),
		),
		mcp.WithString("subject",
			mcp.Required(),
			mcp.Description("Email subject"),
		),
		mcp.WithString("body",
			mcp.Required(),
			mcp.Description("Email body"),
		),
	)
}

func createGoogleDriveTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("file_name",
			mcp.Required(),
			mcp.Description("Name of the file"),
		),
		mcp.WithString("action",
			mcp.Required(),
			mcp.Description("Action to perform (list, create, delete, share)"),
		),
	)
}

func createSlackTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("channel",
			mcp.Required(),
			mcp.Description("Slack channel name or ID"),
		),
		mcp.WithString("message",
			mcp.Required(),
			mcp.Description("Message to send"),
		),
	)
}

// Specific tool creators for dynamic tools
func createGmailSendTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("to",
			mcp.Required(),
			mcp.Description("Recipient email address"),
		),
		mcp.WithString("subject",
			mcp.Required(),
			mcp.Description("Email subject"),
		),
		mcp.WithString("body",
			mcp.Required(),
			mcp.Description("Email body content"),
		),
		mcp.WithString("cc",
			mcp.Description("CC recipient email addresses (comma-separated)"),
		),
	)
}

func createGmailReadTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("query",
			mcp.Description("Gmail search query (e.g., 'is:unread', 'from:example@gmail.com')"),
		),
		mcp.WithNumber("max_results",
			mcp.Description("Maximum number of emails to return (default: 10)"),
		),
	)
}

func createCalendarCreateTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("summary",
			mcp.Required(),
			mcp.Description("Event title/summary"),
		),
		mcp.WithString("start_time",
			mcp.Required(),
			mcp.Description("Start time in ISO 8601 format (e.g., '2024-06-04T10:00:00Z')"),
		),
		mcp.WithString("end_time",
			mcp.Required(),
			mcp.Description("End time in ISO 8601 format (e.g., '2024-06-04T11:00:00Z')"),
		),
		mcp.WithString("description",
			mcp.Description("Event description"),
		),
		mcp.WithString("location",
			mcp.Description("Event location"),
		),
		mcp.WithString("attendees",
			mcp.Description("Comma-separated list of attendee email addresses (user is automatically added as an attendee)"),
		),
	)
}

func createCalendarUpdateTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("event_id",
			mcp.Required(),
			mcp.Description("ID of the event to update"),
		),
		mcp.WithString("summary",
			mcp.Description("Updated event title/summary"),
		),
		mcp.WithString("start_time",
			mcp.Description("Updated start time in ISO 8601 format (e.g., '2024-06-04T10:00:00Z')"),
		),
		mcp.WithString("end_time",
			mcp.Description("Updated end time in ISO 8601 format (e.g., '2024-06-04T11:00:00Z')"),
		),
		mcp.WithString("description",
			mcp.Description("Updated event description"),
		),
		mcp.WithString("location",
			mcp.Description("Updated event location"),
		),
		mcp.WithString("attendees",
			mcp.Description("Updated comma-separated list of attendee email addresses (user is automatically included)"),
		),
		mcp.WithString("calendar_id",
			mcp.Description("Calendar ID (default: 'primary')"),
		),
	)
}

func createCalendarGetTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("time_min",
			mcp.Description("Lower bound (inclusive) for an event's end time (ISO 8601)"),
		),
		mcp.WithString("time_max",
			mcp.Description("Upper bound (exclusive) for an event's start time (ISO 8601)"),
		),
		mcp.WithNumber("max_results",
			mcp.Description("Maximum number of events to return (default: 10)"),
		),
		mcp.WithString("calendar_id",
			mcp.Description("Calendar ID (default: 'primary')"),
		),
	)
}

func createDriveListTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("query",
			mcp.Description("Search query (e.g., 'name contains \"report\"')"),
		),
		mcp.WithNumber("max_results",
			mcp.Description("Maximum number of files to return (default: 10)"),
		),
		mcp.WithString("folder_id",
			mcp.Description("Specific folder ID to search in"),
		),
	)
}

func createDriveCreateTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("name",
			mcp.Required(),
			mcp.Description("File name"),
		),
		mcp.WithString("content",
			mcp.Description("File content (for text files)"),
		),
		mcp.WithString("mime_type",
			mcp.Description("MIME type (e.g., 'text/plain', 'application/vnd.google-apps.document')"),
		),
		mcp.WithString("parent_folder_id",
			mcp.Description("Parent folder ID (optional)"),
		),
	)
}

// GitHub tool creators
func createGitHubTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("owner",
			mcp.Required(),
			mcp.Description("Repository owner (username or organization)"),
		),
		mcp.WithString("repo",
			mcp.Required(),
			mcp.Description("Repository name"),
		),
		mcp.WithString("action",
			mcp.Required(),
			mcp.Description("Action to perform (list, get, contents, file, config)"),
		),
	)
}

func createGitHubRepoTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("owner",
			mcp.Description("Repository owner (optional for listing user repos)"),
		),
		mcp.WithString("repo",
			mcp.Description("Repository name (required for specific repo operations)"),
		),
		mcp.WithString("path",
			mcp.Description("Path within repository (for file/contents operations)"),
		),
		mcp.WithString("visibility",
			mcp.Description("Repository visibility filter (all, public, private)"),
		),
		mcp.WithString("sort",
			mcp.Description("Sort order (created, updated, pushed, full_name)"),
		),
	)
}

func createGitHubIssueTool(name, description string) mcp.Tool {
	return mcp.NewTool(name,
		mcp.WithDescription(description),
		mcp.WithString("owner",
			mcp.Required(),
			mcp.Description("Repository owner (username or organization)"),
		),
		mcp.WithString("repo",
			mcp.Required(),
			mcp.Description("Repository name"),
		),
		mcp.WithString("title",
			mcp.Description("Issue title (required for creating issues)"),
		),
		mcp.WithString("body",
			mcp.Description("Issue body/description"),
		),
		mcp.WithString("labels",
			mcp.Description("Comma-separated list of labels"),
		),
		mcp.WithString("state",
			mcp.Description("Issue state filter (open, closed, all)"),
		),
	)
}

// OAuth configuration for CLI
const (
	clientID     = "mcplocker-cli"
	clientSecret = "mcplocker-cli-secret"
	scope        = "api"
	callbackPort = 38742
)

// handleAuthCommand handles the auth subcommand
func handleAuthCommand(args []string, logger sawmill.Logger, cfg *config.Config) {
	if len(args) == 0 {
		// Default: start OAuth flow
		startOAuthFlow(logger, cfg)
		return
	}

	switch args[0] {
	case "login":
		startOAuthFlow(logger, cfg)
	case "logout":
		handleLogout(logger)
	case "status":
		handleAuthStatus(logger)
	default:
		fmt.Fprintf(os.Stderr, "Unknown auth command: %s\n", args[0])
		fmt.Fprintf(os.Stderr, "Available commands: login, logout, status\n")
		os.Exit(1)
	}
}

// startOAuthFlow initiates the OAuth authorization flow
func startOAuthFlow(logger sawmill.Logger, cfg *config.Config) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// If user already has a token, warn about overwriting
	if cfg.HasValidToken() {
		fmt.Println("⚠️  You already have an authentication token configured.")
		fmt.Println("   This will replace your existing token.")
	}

	// Start local callback server
	callbackURL := fmt.Sprintf("http://localhost:%d/callback", callbackPort)
	authCodeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	// Start HTTP server for OAuth callback
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errChan <- fmt.Errorf("authorization code not received")
			http.Error(w, "Authorization code not received", http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, `
			<html>
			<body>
				<h2>Authorization successful!</h2>
				<p>We will redirect you to configure your 3rd party services shortly!</p>
				<!--<script>window.close();</script>-->
				<script>
				setTimeout(function() {
					window.location.href = "%s";
				}, 1000);
				</script>
			</body>
			</html>
		`, cfg.AuthServerURL)

		authCodeChan <- code
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", callbackPort),
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("failed to start callback server: %w", err)
		}
	}()

	// Build authorization URL
	authURL := buildAuthURL(cfg.AuthServerURL, callbackURL)

	fmt.Printf("Opening browser to authorize MCPLocker CLI...\n")
	fmt.Printf("If the browser doesn't open automatically, visit this URL:\n")
	fmt.Printf("%s\n\n", authURL)

	// Try to open browser (best effort)
	openBrowser(authURL)

	// Wait for authorization code or error
	select {
	case code := <-authCodeChan:
		// Shutdown callback server
		server.Shutdown(context.Background())

		// Exchange code for token
		token, err := exchangeCodeForToken(cfg.AuthServerURL, code, callbackURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to exchange authorization code for token: %v\n", err)
			os.Exit(1)
		}

		// Save token to config (overwrites any existing token)
		cfg.SetToken(token)
		if err := cfg.Save(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to save configuration: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("✅ Authentication successful! Token saved to configuration.")
		fmt.Printf("   Config saved to: %s\n", getConfigPathSafe())
		logger.Info("OAuth authentication completed successfully")

	case err := <-errChan:
		server.Shutdown(context.Background())
		fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
		os.Exit(1)

	case <-time.After(5 * time.Minute):
		server.Shutdown(context.Background())
		fmt.Fprintf(os.Stderr, "Authentication timed out. Please try again.\n")
		os.Exit(1)
	}
}

// buildAuthURL builds the OAuth authorization URL
func buildAuthURL(serverURL, callbackURL string) string {
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", callbackURL)
	params.Add("response_type", "code")
	params.Add("scope", scope)
	params.Add("state", "cli-auth")

	return fmt.Sprintf("%s/api/oauth/authorize?%s", strings.TrimSuffix(serverURL, "/"), params.Encode())
}

// exchangeCodeForToken exchanges authorization code for access token
func exchangeCodeForToken(serverURL, code, callbackURL string) (string, error) {
	tokenURL := fmt.Sprintf("%s/api/oauth/token", strings.TrimSuffix(serverURL, "/"))

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", callbackURL)

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to make token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed with status: %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// openBrowser attempts to open the default browser
func openBrowser(url string) {
	// Cross-platform browser opening (best effort)
	var cmd []string
	switch {
	case os.Getenv("WSL_DISTRO_NAME") != "":
		// Windows Subsystem for Linux
		cmd = []string{"cmd.exe", "/c", "start", url}
	case fileExists("/usr/bin/xdg-open"):
		// Linux
		cmd = []string{"xdg-open", url}
	case fileExists("/usr/bin/open"):
		// macOS
		cmd = []string{"open", url}
	default:
		// Fallback - don't try to open browser
		return
	}

	// Execute command (ignore errors)
	exec := func() {
		if len(cmd) > 0 {
			// Use os.StartProcess or similar to avoid importing os/exec
			// For simplicity, we'll skip the actual execution here
			// In production, you'd use exec.Command(cmd[0], cmd[1:]...).Start()
			_ = exec.Command(cmd[0], cmd[1:]...).Start()
		}
	}
	go exec()
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// getConfigPathSafe safely gets the config path for display
func getConfigPathSafe() string {
	if path, err := config.GetConfigPath(); err == nil {
		return path
	}
	return "~/.config/mcplocker/mcp.json"
}

// isInteractiveTTY checks if the CLI is running in an interactive terminal
func isInteractiveTTY() bool {
	// Check if stdin is a terminal (not piped/redirected)
	if fileInfo, err := os.Stdin.Stat(); err == nil {
		return (fileInfo.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

// handleLogout handles the logout command
func handleLogout(logger sawmill.Logger) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	if !cfg.HasValidToken() {
		fmt.Println("Not currently authenticated.")
		return
	}

	// Clear token from config
	cfg.SetToken("")
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Logged out successfully.")
	logger.Info("User logged out")
}

// handleAuthStatus shows current authentication status
func handleAuthStatus(logger sawmill.Logger) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Auth Server URL: %s\n", cfg.AuthServerURL)

	if cfg.HasValidToken() {
		fmt.Println("Status: ✅ Authenticated")

		// Test connection to server
		authClient := auth.NewClient(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := authClient.Ping(ctx); err != nil {
			fmt.Printf("Connection: ❌ Failed (%v)\n", err)
			fmt.Println("           Run 'mcplocker auth' to re-authenticate.")
		} else {
			fmt.Println("Connection: ✅ Connected")
		}
	} else {
		fmt.Println("Status: ❌ Not authenticated")
		fmt.Println("Run 'mcplocker auth' to authenticate.")
	}
}

// handleConfigCommand handles config-related commands
func handleConfigCommand(args []string, logger sawmill.Logger, cfg *config.Config) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "Config command requires a subcommand\n")
		fmt.Fprintf(os.Stderr, "Available commands: set-server, show\n")
		os.Exit(1)
	}

	switch args[0] {
	case "set-server":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "set-server requires a URL argument\n")
			os.Exit(1)
		}
		handleSetServer(args[1], logger)
	case "show":
		handleShowConfig(logger, cfg)
	default:
		fmt.Fprintf(os.Stderr, "Unknown config command: %s\n", args[0])
		fmt.Fprintf(os.Stderr, "Available commands: set-server, show\n")
		os.Exit(1)
	}
}

// handleSetServer sets the auth server URL
func handleSetServer(serverURL string, logger sawmill.Logger) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	cfg.SetAuthServerURL(serverURL)
	if err := cfg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Auth server URL set to: %s\n", serverURL)
	logger.Info("Auth server URL updated", "url", serverURL)
}

// handleShowConfig shows current configuration
func handleShowConfig(logger sawmill.Logger, cfg *config.Config) {
	fmt.Printf("Auth Server URL: %s\n", cfg.AuthServerURL)
	fmt.Printf("Token Configured: %t\n", cfg.HasValidToken())
	fmt.Printf("Enabled Tools: %d\n", len(cfg.GetEnabledTools()))

	if len(cfg.Tools) > 0 {
		fmt.Println("\nConfigured Tools:")
		for _, tool := range cfg.Tools {
			status := "❌ disabled"
			if tool.Enabled {
				status = "✅ enabled"
			}
			fmt.Printf("  %s (%s/%s) - %s\n", tool.Name, tool.Provider, tool.Service, status)
		}
	}
}

// handleStatusCommand shows overall status
func handleStatusCommand(args []string, logger sawmill.Logger, cfg *config.Config) {
	handleAuthStatus(logger)
	fmt.Println()
	handleShowConfig(logger, cfg)
}

// syncToolsFromAuthServer fetches available tools from auth server and updates local configuration
func syncToolsFromAuthServer(s *server.MCPServer, authClient *auth.Client, cfg *config.Config, logger sawmill.Logger) error {
	// Get available tools from auth server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	availableToolsResp, err := authClient.GetAvailableTools(ctx)
	if err != nil {
		return fmt.Errorf("failed to get available tools from auth server: %w", err)
	}
	
	fmt.Fprintf(os.Stderr, "Auth server returned %d available tools\n", len(availableToolsResp.Tools))
	for _, tool := range availableToolsResp.Tools {
		fmt.Fprintf(os.Stderr, "  Available: %s (%s/%s)\n", tool.Name, tool.Provider, tool.Service)
	}

	// Track currently configured tools to avoid duplicates
	currentTools := make(map[string]bool)
	enabledTools := cfg.GetEnabledTools()
	fmt.Fprintf(os.Stderr, "Currently have %d tools configured locally\n", len(enabledTools))
	for _, tool := range enabledTools {
		currentTools[tool.Name] = true
		fmt.Fprintf(os.Stderr, "  - %s (%s/%s)\n", tool.Name, tool.Provider, tool.Service)
	}

	// Check for new tools and add them
	newToolsAdded := false
	for _, toolConfig := range availableToolsResp.Tools {
		if !currentTools[toolConfig.Name] {
			// New tool found, add it to local config
			logger.Info("Adding new tool from auth server", "tool", toolConfig.Name, "provider", toolConfig.Provider, "service", toolConfig.Service)
			cfg.AddTool(toolConfig)
			newToolsAdded = true
		}
	}

	// Save updated configuration if new tools were added
	if newToolsAdded {
		if err := cfg.Save(); err != nil {
			logger.Error("Failed to save updated configuration", "error", err)
			return fmt.Errorf("failed to save updated configuration: %w", err)
		}
		logger.Info("Configuration updated with tools from auth server")
		fmt.Fprintf(os.Stderr, "Synced tools from auth server. %d tools now configured.\n", len(cfg.GetEnabledTools()))
	} else {
		logger.Info("No new tools found on auth server")
	}

	return nil
}

// startToolPolling polls the auth server for available tools and updates the MCP server
func startToolPolling(s *server.MCPServer, authClient *auth.Client, cfg *config.Config, logger sawmill.Logger, cancel context.CancelFunc) {
	ticker := time.NewTicker(5 * time.Second) // Poll every 5 seconds for better responsiveness
	defer ticker.Stop()

	// Track currently added tools to avoid duplicates
	currentTools := make(map[string]bool)
	for _, tool := range cfg.GetEnabledTools() {
		currentTools[tool.Name] = true
	}

	logger.Info("Started tool polling", "interval", "5 seconds")

	for {
		select {
		case <-ticker.C:
			// Poll for available tools
			ctx, pollCancel := context.WithTimeout(context.Background(), 10*time.Second)
			availableToolsResp, err := authClient.GetAvailableTools(ctx)
			pollCancel()

			if err != nil {
				logger.Warn("Failed to poll for available tools", "error", err)
				continue
			}

			// Create a map of tools currently available from auth server
			availableTools := make(map[string]bool)
			for _, toolConfig := range availableToolsResp.Tools {
				availableTools[toolConfig.Name] = true
			}

			// Check for new tools to add
			newTools := false
			for _, toolConfig := range availableToolsResp.Tools {
				if !currentTools[toolConfig.Name] {
					// New tool found, add it to the server
					logger.Info("Adding new tool", "tool", toolConfig.Name, "provider", toolConfig.Provider, "service", toolConfig.Service)
					addProxyTool(s, toolConfig, authClient, logger)

					// Add to local config
					cfg.AddTool(toolConfig)
					currentTools[toolConfig.Name] = true
					newTools = true
				}
			}

			// Check for tools that are no longer available (service disconnected)
			toolsRemoved := false
			for toolName := range currentTools {
				if !availableTools[toolName] {
					// Tool is no longer available, remove it
					logger.Info("Removing unavailable tool", "tool", toolName)
					if cfg.RemoveTool(toolName) {
						delete(currentTools, toolName)
						toolsRemoved = true
						fmt.Fprintf(os.Stderr, "Service disconnected: tool %s removed\n", toolName)
					}
				}
			}

			// Save updated configuration if tools were added or removed
			configChanged := newTools || toolsRemoved
			if configChanged {
				if err := cfg.Save(); err != nil {
					logger.Error("Failed to save updated configuration", "error", err)
				} else {
					if newTools && toolsRemoved {
						logger.Info("Configuration updated: tools added and removed")
						fmt.Fprintf(os.Stderr, "Tools updated! %d tools now configured.\n", len(cfg.GetEnabledTools()))
					} else if newTools {
						logger.Info("Configuration updated with new tools")
						fmt.Fprintf(os.Stderr, "New tools available! %d tools now configured.\n", len(cfg.GetEnabledTools()))
					} else if toolsRemoved {
						logger.Info("Configuration updated: removed disconnected tools")
						fmt.Fprintf(os.Stderr, "Disconnected tools removed. %d tools now configured.\n", len(cfg.GetEnabledTools()))
					}
					
					// Send tool list changed notification to all connected MCP clients
					s.SendNotificationToAllClients("notifications/tools/list_changed", nil)
					logger.Info("Sent tool list changed notification to MCP clients")
				}
			}

		case <-context.Background().Done():
			logger.Info("Tool polling stopped")
			return
		}
	}
}

// startToolChangeListener listens for real-time tool changes from the auth server
func startToolChangeListener(s *server.MCPServer, authClient *auth.Client, cfg *config.Config, logger sawmill.Logger, cancel context.CancelFunc) {
	// Suppress unused parameter warnings
	_ = s
	_ = authClient
	_ = cfg
	_ = cancel
	logger.Info("Started tool change listener for real-time updates")
	
	for {
		select {
		case <-context.Background().Done():
			logger.Info("Tool change listener stopped")
			return
		default:
			// For now, just wait before next check
			// TODO: Implement tool changes endpoint in auth client
			time.Sleep(2 * time.Second)
		}
	}
}
