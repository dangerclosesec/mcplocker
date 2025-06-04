package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bresrch/sawmill"
	"github.com/dangerclosesec/mcplocker"
	"github.com/dangerclosesec/mcplocker/internal/auth"
	"github.com/dangerclosesec/mcplocker/internal/config"
	"github.com/dangerclosesec/mcplocker/internal/web"
	"golang.org/x/oauth2"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	// Global flags
	debug bool
	
	// In-memory storage (use database in production)
	authCodes           = make(map[string]*AuthCode)
	accessTokens        = make(map[string]*AccessToken)
	apiTokens           = make(map[string]*APIToken)
	pendingOAuthRequests = make(map[string]*OAuthRequest)
	storageMutex        = sync.RWMutex{}
)

// AuthCode represents an OAuth authorization code
type AuthCode struct {
	Code        string
	ClientID    string
	UserID      string
	ExpiresAt   time.Time
	RedirectURI string
	Scope       string
}

// AccessToken represents an OAuth access token
type AccessToken struct {
	Token     string
	UserID    string
	ClientID  string
	ExpiresAt time.Time
	Scope     string
}

// APIToken represents a long-lived API token for CLI access
type APIToken struct {
	ID          string
	Name        string
	Token       string
	UserID      string
	CreatedAt   time.Time
	LastUsed    *time.Time
	ExpiresAt   *time.Time
	Permissions []string
}

// OAuthClient represents a registered OAuth client
type OAuthClient struct {
	ID           string
	Secret       string
	Name         string
	RedirectURIs []string
}

// OAuthRequest represents a pending OAuth authorization request
type OAuthRequest struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	ExpiresAt   time.Time
}

// Built-in OAuth client for mcplocker CLI
var mcplockerClient = &OAuthClient{
	ID:     "mcplocker-cli",
	Secret: "mcplocker-cli-secret", // In production, use a secure secret
	Name:   "MCPLocker CLI",
	RedirectURIs: []string{
		"http://localhost:38742/callback", // CLI callback port
		"urn:ietf:wg:oauth:2.0:oob",      // Out-of-band flow
	},
}

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

	// Initialize web handlers
	webHandlers := web.NewWebHandlers()

	// Web UI routes (public and authenticated pages)
	webHandlers.RegisterRoutes(r)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})

	// API endpoints for CLI tool communication
	r.Route("/api", func(r chi.Router) {
		// Auth endpoints
		r.Route("/auth", func(r chi.Router) {
			r.Post("/start", handleAuthStart)
			r.Get("/validate", handleAuthValidate)
			r.Get("/callback/{provider}", handleAuthCallback)
		})

		// OAuth authorization server endpoints for CLI
		r.Route("/oauth", func(r chi.Router) {
			r.Get("/authorize", makeOAuthAuthorizeHandler(webHandlers))
			r.Post("/token", handleOAuthToken)
			r.Post("/revoke", handleOAuthRevoke)
			r.Get("/complete", makeOAuthCompleteHandler(webHandlers))
		})

		// API tokens management
		r.Route("/tokens", func(r chi.Router) {
			r.Use(makeWebAuthMiddleware(webHandlers)) // Require web session authentication
			r.Get("/", makeListTokensHandler(webHandlers))
			r.Post("/", makeCreateTokenHandler(webHandlers))
			r.Delete("/{tokenId}", makeRevokeTokenHandler(webHandlers))
		})

		// Proxy endpoints
		r.Route("/proxy", func(r chi.Router) {
			r.Use(authMiddleware)
			r.Post("/tool", makeProxyToolHandler(webHandlers))
		})

		// Tool management endpoints
		r.Route("/tools", func(r chi.Router) {
			r.Use(authMiddleware)
			r.Get("/status", handleToolStatus)
			r.Get("/available", makeAvailableToolsHandler(webHandlers))
		})
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

// authMiddleware validates the authentication token (OAuth or API token)
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" || token == authHeader {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		hashedToken := hashToken(token)
		
		storageMutex.RLock()
		defer storageMutex.RUnlock()
		
		// Check OAuth access tokens
		if accessToken, exists := accessTokens[hashedToken]; exists {
			if accessToken.ExpiresAt.After(time.Now()) {
				// Add user context to request
				ctx := context.WithValue(r.Context(), "userID", accessToken.UserID)
				ctx = context.WithValue(ctx, "clientID", accessToken.ClientID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// Clean up expired token
			delete(accessTokens, hashedToken)
		}
		
		// Check API tokens
		for _, apiToken := range apiTokens {
			if apiToken.Token == hashedToken {
				if apiToken.ExpiresAt == nil || apiToken.ExpiresAt.After(time.Now()) {
					// Update last used timestamp
					apiToken.LastUsed = &[]time.Time{time.Now()}[0]
					
					// Add user context to request
					ctx := context.WithValue(r.Context(), "userID", apiToken.UserID)
					ctx = context.WithValue(ctx, "tokenID", apiToken.ID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
		}

		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
	})
}

// handleAuthStart initiates the OAuth flow for a provider/service
func handleAuthStart(w http.ResponseWriter, r *http.Request) {
	var req auth.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var authURL string
	var err error

	switch req.Provider {
	case "google":
		authURL, err = buildGoogleAuthURL(req.Service)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to build Google auth URL: %v", err), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, fmt.Sprintf("Unsupported provider: %s", req.Provider), http.StatusBadRequest)
		return
	}

	resp := auth.AuthResponse{
		Success: true,
		AuthURL: authURL,
		Message: fmt.Sprintf("Please visit the auth URL to authenticate %s %s", req.Provider, req.Service),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// buildGoogleAuthURL constructs the Google OAuth authorization URL
func buildGoogleAuthURL(service string) (string, error) {
	googleConfig, err := config.LoadGoogleConfig()
	if err != nil {
		return "", fmt.Errorf("failed to load Google config: %w", err)
	}

	// Define scopes based on the service
	var scopes []string
	switch service {
	case "calendar":
		scopes = []string{
			"https://www.googleapis.com/auth/calendar",
			"https://www.googleapis.com/auth/calendar.events",
		}
	case "gmail":
		scopes = []string{
			"https://www.googleapis.com/auth/gmail.send",
			"https://www.googleapis.com/auth/gmail.readonly",
		}
	case "drive":
		scopes = []string{
			"https://www.googleapis.com/auth/drive",
			"https://www.googleapis.com/auth/drive.file",
		}
	default:
		scopes = []string{"https://www.googleapis.com/auth/userinfo.profile"}
	}

	// Build the authorization URL
	params := url.Values{}
	params.Add("client_id", googleConfig.GetClientID())
	params.Add("redirect_uri", googleConfig.GetRedirectURI())
	params.Add("scope", strings.Join(scopes, " "))
	params.Add("response_type", "code")
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")
	params.Add("state", service) // Use service as state to track which service is being authenticated

	authURL := googleConfig.GetAuthURI() + "?" + params.Encode()
	return authURL, nil
}

// handleAuthValidate validates the current authentication token
func handleAuthValidate(w http.ResponseWriter, r *http.Request) {
	// If we reach here, the authMiddleware has already validated the token
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleAuthCallback handles OAuth callbacks from providers
func handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	
	if code == "" {
		http.Error(w, "Authorization code not provided", http.StatusBadRequest)
		return
	}

	switch provider {
	case "google":
		if err := handleGoogleCallback(code, state); err != nil {
			http.Error(w, fmt.Sprintf("Failed to complete Google authentication: %v", err), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, fmt.Sprintf("Unsupported provider: %s", provider), http.StatusBadRequest)
		return
	}

	fmt.Fprintf(w, "Successfully authenticated with %s %s. You can close this window.", provider, state)
}

// handleGoogleCallback exchanges the authorization code for access and refresh tokens
func handleGoogleCallback(code, service string) error {
	googleConfig, err := config.LoadGoogleConfig()
	if err != nil {
		return fmt.Errorf("failed to load Google config: %w", err)
	}

	// Prepare token exchange request
	tokenURL := googleConfig.GetTokenURI()
	data := url.Values{}
	data.Set("client_id", googleConfig.GetClientID())
	data.Set("client_secret", googleConfig.GetClientSecret())
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", googleConfig.GetRedirectURI())

	// Make the token exchange request
	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
	}

	// Parse the token response
	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	// TODO: Store tokens securely (database, encrypted file, etc.)
	// For now, just log that we received them
	fmt.Printf("Received tokens for Google %s service:\n", service)
	fmt.Printf("Access Token: %s...\n", tokenResp.AccessToken[:20])
	if tokenResp.RefreshToken != "" {
		fmt.Printf("Refresh Token: %s...\n", tokenResp.RefreshToken[:20])
	}
	fmt.Printf("Expires In: %d seconds\n", tokenResp.ExpiresIn)

	return nil
}

// makeProxyToolHandler creates a proxy tool handler with access to webHandlers
func makeProxyToolHandler(webHandlers *web.WebHandlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleProxyToolWithWebHandlers(w, r, webHandlers)
	}
}

// handleProxyToolWithWebHandlers proxies tool calls to the appropriate provider
func handleProxyToolWithWebHandlers(w http.ResponseWriter, r *http.Request, webHandlers *web.WebHandlers) {
	var req auth.ProxyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		fmt.Printf("DEBUG: Failed to decode proxy request body: %v\n", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	fmt.Printf("DEBUG: Received proxy tool request - Tool: %s, Parameters: %+v\n", req.ToolName, req.Parameters)

	// Get user ID from token authentication context
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		fmt.Printf("DEBUG: User ID not found in request context\n")
		http.Error(w, "User ID not found in request context", http.StatusUnauthorized)
		return
	}
	
	fmt.Printf("DEBUG: Authenticated user ID: %s\n", userID)

	// Determine service based on tool name
	service := getServiceFromToolName(req.ToolName)
	fmt.Printf("DEBUG: Mapped tool %s to service: %s\n", req.ToolName, service)
	if service == "" {
		fmt.Printf("DEBUG: Unknown tool name: %s\n", req.ToolName)
		resp := auth.ProxyResponse{
			Success: false,
			Error:   fmt.Sprintf("Unknown tool: %s", req.ToolName),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Get user's service credentials
	tokenKey := userID + ":" + service
	fmt.Printf("DEBUG: Looking up service connection with key: %s\n", tokenKey)
	serviceConnection, exists := webHandlers.GetServiceConnection(tokenKey)
	if !exists {
		fmt.Printf("DEBUG: Service connection not found for key: %s\n", tokenKey)
		resp := auth.ProxyResponse{
			Success: false,
			Error:   fmt.Sprintf("Service %s not authenticated for user", service),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	
	fmt.Printf("DEBUG: Found service connection for %s\n", service)

	// Check if token is still valid
	if serviceConnection.Token == nil || !serviceConnection.Token.Valid() {
		fmt.Printf("DEBUG: Service token is invalid or expired for %s\n", service)
		resp := auth.ProxyResponse{
			Success: false,
			Error:   fmt.Sprintf("Service %s token expired, please re-authenticate", service),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	
	fmt.Printf("DEBUG: Service token is valid for %s\n", service)

	// Execute the actual tool call with the user's service credentials
	fmt.Printf("DEBUG: Executing tool call for %s with parameters: %+v\n", req.ToolName, req.Parameters)
	result, err := executeToolCall(req.ToolName, req.Parameters, serviceConnection.Token)
	if err != nil {
		fmt.Printf("DEBUG: Tool execution failed: %v\n", err)
		resp := auth.ProxyResponse{
			Success: false,
			Error:   fmt.Sprintf("Tool execution failed: %v", err),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	
	fmt.Printf("DEBUG: Tool execution successful, result: %+v\n", result)

	resp := auth.ProxyResponse{
		Success: true,
		Result:  result,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleToolStatus returns the status of all configured tools
func handleToolStatus(w http.ResponseWriter, r *http.Request) {
	// TODO: Return actual tool configurations from storage
	// For now, return some mock tools
	resp := auth.ToolStatusResponse{
		Tools: []config.ToolConfig{
			{
				Name:          "google_calendar_create_event",
				Provider:      "google",
				Service:       "calendar",
				Enabled:       true,
				Authenticated: true,
			},
			{
				Name:          "slack_send_message",
				Provider:      "slack",
				Service:       "messages",
				Enabled:       true,
				Authenticated: false,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// makeWebAuthMiddleware creates a web authentication middleware using webHandlers
func makeWebAuthMiddleware(webHandlers *web.WebHandlers) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use webHandlers to validate user session
			user := webHandlers.GetUser(r)
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			// Add user to request context
			ctx := context.WithValue(r.Context(), "user", user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// hashToken creates a SHA256 hash of the token for storage
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// makeOAuthAuthorizeHandler creates an OAuth authorize handler with webHandlers
func makeOAuthAuthorizeHandler(webHandlers *web.WebHandlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleOAuthAuthorizeWithWebHandlers(w, r, webHandlers)
	}
}

// handleOAuthAuthorizeWithWebHandlers handles the OAuth authorization endpoint
func handleOAuthAuthorizeWithWebHandlers(w http.ResponseWriter, r *http.Request, webHandlers *web.WebHandlers) {
	// Parse query parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	responseType := r.URL.Query().Get("response_type")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType != "code" {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	// Validate client
	if clientID != mcplockerClient.ID {
		http.Error(w, "Invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	validRedirectURI := false
	for _, uri := range mcplockerClient.RedirectURIs {
		if uri == redirectURI {
			validRedirectURI = true
			break
		}
	}
	if !validRedirectURI {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Check if user is authenticated (has web session)
	user := webHandlers.GetUser(r)
	if user == nil {
		// Store OAuth request parameters in a temporary store for after login
		oauthStateKey := generateSecureToken()
		oauthRequest := &OAuthRequest{
			ClientID:     clientID,
			RedirectURI:  redirectURI,
			Scope:        scope,
			State:        state,
			ExpiresAt:    time.Now().Add(30 * time.Minute),
		}
		
		storageMutex.Lock()
		pendingOAuthRequests[oauthStateKey] = oauthRequest
		storageMutex.Unlock()
		
		// Store return URL in cookie for after login
		returnURL := fmt.Sprintf("/api/oauth/complete?oauth_state=%s", oauthStateKey)
		http.SetCookie(w, &http.Cookie{
			Name:     "return_to",
			Value:    returnURL,
			Path:     "/",
			MaxAge:   1800, // 30 minutes
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
		})
		
		// Redirect to login page
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Get user ID from authenticated session
	userID := user.ID

	// Generate authorization code
	code := generateSecureToken()
	authCode := &AuthCode{
		Code:        code,
		ClientID:    clientID,
		UserID:      userID,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		RedirectURI: redirectURI,
		Scope:       scope,
	}

	storageMutex.Lock()
	authCodes[code] = authCode
	storageMutex.Unlock()

	// Redirect back to client with authorization code
	redirectURL, _ := url.Parse(redirectURI)
	query := redirectURL.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
}

// handleOAuthToken handles the OAuth token exchange endpoint
func handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	// Parse form data
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// Validate client credentials
	if clientID != mcplockerClient.ID || clientSecret != mcplockerClient.Secret {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	switch grantType {
	case "authorization_code":
		handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		handleRefreshTokenGrant(w, r)
	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
	}
}

// handleAuthorizationCodeGrant handles the authorization code grant flow
func handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	// Validate authorization code
	storageMutex.RLock()
	authCode, exists := authCodes[code]
	storageMutex.RUnlock()

	if !exists || authCode.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Invalid or expired authorization code", http.StatusBadRequest)
		return
	}

	if authCode.RedirectURI != redirectURI {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Generate access token
	accessToken := generateSecureToken()
	refreshToken := generateSecureToken()

	token := &AccessToken{
		Token:     hashToken(accessToken),
		UserID:    authCode.UserID,
		ClientID:  authCode.ClientID,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Scope:     authCode.Scope,
	}

	storageMutex.Lock()
	accessTokens[token.Token] = token
	delete(authCodes, code) // Clean up used auth code
	storageMutex.Unlock()

	// Return token response
	response := map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"scope":         authCode.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRefreshTokenGrant handles the refresh token grant flow
func handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement refresh token logic
	http.Error(w, "Refresh token grant not implemented", http.StatusNotImplemented)
}

// handleOAuthRevoke handles token revocation
func handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}

	hashedToken := hashToken(token)

	storageMutex.Lock()
	delete(accessTokens, hashedToken)
	// Also check API tokens
	for id, apiToken := range apiTokens {
		if apiToken.Token == hashedToken {
			delete(apiTokens, id)
			break
		}
	}
	storageMutex.Unlock()

	w.WriteHeader(http.StatusOK)
}

// handleListTokens returns a list of API tokens for the authenticated user
func handleListTokens(w http.ResponseWriter, r *http.Request) {
	// TODO: Get user ID from session
	cookie, _ := r.Cookie("session")
	userID := "user-" + cookie.Value

	storageMutex.RLock()
	var userTokens []*APIToken
	for _, token := range apiTokens {
		if token.UserID == userID {
			userTokens = append(userTokens, token)
		}
	}
	storageMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userTokens)
}

// handleCreateToken creates a new API token for the authenticated user
func handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
		ExpiresIn   *int     `json:"expires_in"` // Optional expiration in seconds
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "Token name is required", http.StatusBadRequest)
		return
	}

	// TODO: Get user ID from session
	cookie, _ := r.Cookie("session")
	userID := "user-" + cookie.Value

	// Generate token
	token := generateSecureToken()
	tokenID := generateSecureToken()[:16] // Shorter ID for display

	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		exp := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &exp
	}

	apiToken := &APIToken{
		ID:          tokenID,
		Name:        req.Name,
		Token:       hashToken(token),
		UserID:      userID,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Permissions: req.Permissions,
	}

	storageMutex.Lock()
	apiTokens[tokenID] = apiToken
	storageMutex.Unlock()

	// Return the token (only time it's shown in plain text)
	response := struct {
		*APIToken
		PlainToken string `json:"token"`
	}{
		APIToken:   apiToken,
		PlainToken: token,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleRevokeToken revokes an API token
func handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "tokenId")
	
	// TODO: Get user ID from session and validate ownership
	cookie, _ := r.Cookie("session")
	userID := "user-" + cookie.Value

	storageMutex.Lock()
	token, exists := apiTokens[tokenID]
	if exists && token.UserID == userID {
		delete(apiTokens, tokenID)
	}
	storageMutex.Unlock()

	if !exists {
		http.Error(w, "Token not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// makeOAuthCompleteHandler creates an OAuth complete handler with webHandlers
func makeOAuthCompleteHandler(webHandlers *web.WebHandlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handleOAuthCompleteWithWebHandlers(w, r, webHandlers)
	}
}

// handleOAuthCompleteWithWebHandlers completes OAuth authorization after user login
func handleOAuthCompleteWithWebHandlers(w http.ResponseWriter, r *http.Request, webHandlers *web.WebHandlers) {
	oauthStateKey := r.URL.Query().Get("oauth_state")
	if oauthStateKey == "" {
		http.Error(w, "Missing OAuth state parameter", http.StatusBadRequest)
		return
	}

	// Check if user is now authenticated
	user := webHandlers.GetUser(r)
	if user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	// Retrieve the pending OAuth request
	storageMutex.RLock()
	oauthRequest, exists := pendingOAuthRequests[oauthStateKey]
	storageMutex.RUnlock()

	if !exists || oauthRequest.ExpiresAt.Before(time.Now()) {
		http.Error(w, "Invalid or expired OAuth request", http.StatusBadRequest)
		return
	}

	// Clean up the pending request
	storageMutex.Lock()
	delete(pendingOAuthRequests, oauthStateKey)
	storageMutex.Unlock()

	// Get user ID from authenticated session
	userID := user.ID

	// Generate authorization code
	code := generateSecureToken()
	authCode := &AuthCode{
		Code:        code,
		ClientID:    oauthRequest.ClientID,
		UserID:      userID,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		RedirectURI: oauthRequest.RedirectURI,
		Scope:       oauthRequest.Scope,
	}

	storageMutex.Lock()
	authCodes[code] = authCode
	storageMutex.Unlock()

	// Redirect back to client with authorization code
	redirectURL, _ := url.Parse(oauthRequest.RedirectURI)
	query := redirectURL.Query()
	query.Set("code", code)
	if oauthRequest.State != "" {
		query.Set("state", oauthRequest.State)
	}
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusSeeOther)
}

// makeListTokensHandler creates a list tokens handler with webHandlers
func makeListTokensHandler(webHandlers *web.WebHandlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := webHandlers.GetUser(r) // Already validated by middleware
		if user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		storageMutex.RLock()
		var userTokens []*APIToken
		for _, token := range apiTokens {
			if token.UserID == user.ID {
				userTokens = append(userTokens, token)
			}
		}
		storageMutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userTokens)
	}
}

// makeCreateTokenHandler creates a create token handler with webHandlers
func makeCreateTokenHandler(webHandlers *web.WebHandlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := webHandlers.GetUser(r) // Already validated by middleware
		if user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		var req struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
			ExpiresIn   *int     `json:"expires_in"` // Optional expiration in seconds
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.Name == "" {
			http.Error(w, "Token name is required", http.StatusBadRequest)
			return
		}

		// Generate token
		token := generateSecureToken()
		tokenID := generateSecureToken()[:16] // Shorter ID for display

		var expiresAt *time.Time
		if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
			exp := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Second)
			expiresAt = &exp
		}

		apiToken := &APIToken{
			ID:          tokenID,
			Name:        req.Name,
			Token:       hashToken(token),
			UserID:      user.ID,
			CreatedAt:   time.Now(),
			ExpiresAt:   expiresAt,
			Permissions: req.Permissions,
		}

		storageMutex.Lock()
		apiTokens[tokenID] = apiToken
		storageMutex.Unlock()

		// Return the token (only time it's shown in plain text)
		response := struct {
			*APIToken
			PlainToken string `json:"token"`
		}{
			APIToken:   apiToken,
			PlainToken: token,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// makeRevokeTokenHandler creates a revoke token handler with webHandlers
func makeRevokeTokenHandler(webHandlers *web.WebHandlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := webHandlers.GetUser(r) // Already validated by middleware
		if user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		tokenID := chi.URLParam(r, "tokenId")

		storageMutex.Lock()
		token, exists := apiTokens[tokenID]
		if exists && token.UserID == user.ID {
			delete(apiTokens, tokenID)
		}
		storageMutex.Unlock()

		if !exists {
			http.Error(w, "Token not found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

// getServiceFromToolName extracts the service name from a tool name
func getServiceFromToolName(toolName string) string {
	switch {
	case strings.Contains(toolName, "gmail"):
		return "gmail"
	case strings.Contains(toolName, "calendar"):
		return "calendar"
	case strings.Contains(toolName, "drive"):
		return "drive"
	case strings.Contains(toolName, "slack"):
		return "slack"
	default:
		return ""
	}
}


// executeToolCall executes the actual API call for a tool using service credentials
func executeToolCall(toolName string, parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	service := getServiceFromToolName(toolName)
	
	switch service {
	case "gmail":
		return executeGmailTool(toolName, parameters, token)
	case "calendar":
		return executeCalendarTool(toolName, parameters, token)
	case "drive":
		return executeDriveTool(toolName, parameters, token)
	default:
		return nil, fmt.Errorf("unsupported service: %s", service)
	}
}

// executeGmailTool executes Gmail API calls
func executeGmailTool(toolName string, parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	// TODO: Implement actual Gmail API calls
	// For now, return a mock response with the authenticated user context
	return map[string]interface{}{
		"message": fmt.Sprintf("Gmail tool %s executed successfully", toolName),
		"parameters": parameters,
		"authenticated": true,
		"user_email": "user@example.com", // This would come from the token
	}, nil
}

// executeCalendarTool executes Google Calendar API calls  
func executeCalendarTool(toolName string, parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	fmt.Printf("DEBUG: executeCalendarTool called with tool: %s, parameters: %+v\n", toolName, parameters)
	fmt.Printf("DEBUG: OAuth token valid: %t, expires: %v\n", token.Valid(), token.Expiry)
	
	switch toolName {
	case "calendar_create_event":
		return createCalendarEvent(parameters, token)
	case "calendar_get_events":
		return getCalendarEvents(parameters, token)
	default:
		return nil, fmt.Errorf("unsupported calendar tool: %s", toolName)
	}
}

// executeDriveTool executes Google Drive API calls
func executeDriveTool(toolName string, parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	// TODO: Implement actual Drive API calls
	// For now, return a mock response with the authenticated user context
	return map[string]interface{}{
		"message": fmt.Sprintf("Drive tool %s executed successfully", toolName),
		"parameters": parameters,
		"authenticated": true,
		"user_email": "user@example.com", // This would come from the token
	}, nil
}

// makeAvailableToolsHandler creates a handler that returns available tools based on user's authenticated services
func makeAvailableToolsHandler(webHandlers *web.WebHandlers) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user from token authentication (already validated by authMiddleware)
		userID := r.Context().Value("userID").(string)
		
		// Get available tools based on authenticated services
		availableTools := getAvailableToolsForUser(userID, webHandlers)
		
		response := struct {
			Tools []config.ToolConfig `json:"tools"`
		}{
			Tools: availableTools,
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// getAvailableToolsForUser returns tools available based on user's authenticated services
func getAvailableToolsForUser(userID string, webHandlers *web.WebHandlers) []config.ToolConfig {
	var tools []config.ToolConfig
	
	// Check which services the user has authenticated
	// We need to get the user from the web handlers to check service connections
	// For now, we'll check the service tokens directly
	
	storageMutex.RLock()
	defer storageMutex.RUnlock()
	
	// Check Google services
	services := []string{"gmail", "calendar", "drive"}
	for _, service := range services {
		tokenKey := userID + ":" + service
		if connection, exists := webHandlers.GetServiceConnection(tokenKey); exists && connection.Token != nil && connection.Token.Valid() {
			// Add tools for this authenticated service
			switch service {
			case "gmail":
				tools = append(tools, config.ToolConfig{
					Name:          "gmail_send_email",
					Provider:      "google",
					Service:       "gmail",
					Enabled:       true,
					Authenticated: true,
				})
				tools = append(tools, config.ToolConfig{
					Name:          "gmail_read_emails",
					Provider:      "google", 
					Service:       "gmail",
					Enabled:       true,
					Authenticated: true,
				})
			case "calendar":
				tools = append(tools, config.ToolConfig{
					Name:          "calendar_create_event",
					Provider:      "google",
					Service:       "calendar", 
					Enabled:       true,
					Authenticated: true,
				})
				tools = append(tools, config.ToolConfig{
					Name:          "calendar_get_events",
					Provider:      "google",
					Service:       "calendar",
					Enabled:       true,
					Authenticated: true,
				})
			case "drive":
				tools = append(tools, config.ToolConfig{
					Name:          "drive_list_files",
					Provider:      "google",
					Service:       "drive",
					Enabled:       true,
					Authenticated: true,
				})
				tools = append(tools, config.ToolConfig{
					Name:          "drive_create_file",
					Provider:      "google",
					Service:       "drive", 
					Enabled:       true,
					Authenticated: true,
				})
			}
		}
	}
	
	fmt.Printf("Returning %d tools for user %s\n", len(tools), userID)
	return tools
}

// createCalendarEvent creates a new calendar event using Google Calendar API
func createCalendarEvent(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	// Create OAuth2 client with the user's token
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	
	// Create Calendar service
	service, err := calendar.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar service: %w", err)
	}

	// Extract parameters
	summary, ok := parameters["summary"].(string)
	if !ok {
		return nil, fmt.Errorf("summary parameter is required and must be a string")
	}

	startTime, ok := parameters["start_time"].(string)
	if !ok {
		return nil, fmt.Errorf("start_time parameter is required and must be a string")
	}

	endTime, ok := parameters["end_time"].(string)
	if !ok {
		return nil, fmt.Errorf("end_time parameter is required and must be a string")
	}

	// Parse times
	startDateTime, err := time.Parse(time.RFC3339, startTime)
	if err != nil {
		return nil, fmt.Errorf("invalid start_time format, expected RFC3339: %w", err)
	}

	endDateTime, err := time.Parse(time.RFC3339, endTime)
	if err != nil {
		return nil, fmt.Errorf("invalid end_time format, expected RFC3339: %w", err)
	}

	// Create the event
	event := &calendar.Event{
		Summary: summary,
		Start: &calendar.EventDateTime{
			DateTime: startDateTime.Format(time.RFC3339),
			TimeZone: "UTC",
		},
		End: &calendar.EventDateTime{
			DateTime: endDateTime.Format(time.RFC3339),
			TimeZone: "UTC",
		},
	}

	// Add optional fields
	if description, ok := parameters["description"].(string); ok && description != "" {
		event.Description = description
	}

	if location, ok := parameters["location"].(string); ok && location != "" {
		event.Location = location
	}

	// Add attendees if provided
	if attendeesStr, ok := parameters["attendees"].(string); ok && attendeesStr != "" {
		attendeeEmails := strings.Split(attendeesStr, ",")
		var attendees []*calendar.EventAttendee
		for _, email := range attendeeEmails {
			email = strings.TrimSpace(email)
			if email != "" {
				attendees = append(attendees, &calendar.EventAttendee{
					Email: email,
				})
			}
		}
		event.Attendees = attendees
	}

	// Insert the event (default to primary calendar)
	calendarID := "primary"
	if calID, ok := parameters["calendar_id"].(string); ok && calID != "" {
		calendarID = calID
	}

	createdEvent, err := service.Events.Insert(calendarID, event).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar event: %w", err)
	}

	// Return success response
	result := map[string]interface{}{
		"success":      true,
		"message":      "Calendar event created successfully",
		"event_id":     createdEvent.Id,
		"event_link":   createdEvent.HtmlLink,
		"summary":      createdEvent.Summary,
		"start_time":   createdEvent.Start.DateTime,
		"end_time":     createdEvent.End.DateTime,
		"created":      createdEvent.Created,
		"calendar_id":  calendarID,
	}

	fmt.Printf("DEBUG: Successfully created calendar event: %s (ID: %s)\n", createdEvent.Summary, createdEvent.Id)
	return result, nil
}

// getCalendarEvents retrieves calendar events using Google Calendar API
func getCalendarEvents(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	// Create OAuth2 client with the user's token
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	
	// Create Calendar service
	service, err := calendar.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar service: %w", err)
	}

	// Set up query parameters
	calendarID := "primary"
	if calID, ok := parameters["calendar_id"].(string); ok && calID != "" {
		calendarID = calID
	}

	call := service.Events.List(calendarID)

	// Add optional time bounds
	if timeMin, ok := parameters["time_min"].(string); ok && timeMin != "" {
		call = call.TimeMin(timeMin)
	}

	if timeMax, ok := parameters["time_max"].(string); ok && timeMax != "" {
		call = call.TimeMax(timeMax)
	}

	// Set max results
	maxResults := int64(10)
	if maxRes, ok := parameters["max_results"].(float64); ok && maxRes > 0 {
		maxResults = int64(maxRes)
	}
	call = call.MaxResults(maxResults)

	// Execute the query
	events, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve calendar events: %w", err)
	}

	// Format the response
	var eventList []map[string]interface{}
	for _, event := range events.Items {
		eventInfo := map[string]interface{}{
			"id":          event.Id,
			"summary":     event.Summary,
			"description": event.Description,
			"location":    event.Location,
			"start_time":  event.Start.DateTime,
			"end_time":    event.End.DateTime,
			"html_link":   event.HtmlLink,
			"created":     event.Created,
			"updated":     event.Updated,
		}

		// Add attendees if present
		if len(event.Attendees) > 0 {
			var attendees []string
			for _, attendee := range event.Attendees {
				attendees = append(attendees, attendee.Email)
			}
			eventInfo["attendees"] = attendees
		}

		eventList = append(eventList, eventInfo)
	}

	result := map[string]interface{}{
		"success":     true,
		"message":     "Calendar events retrieved successfully",
		"events":      eventList,
		"total_count": len(eventList),
		"calendar_id": calendarID,
	}

	fmt.Printf("DEBUG: Retrieved %d calendar events\n", len(eventList))
	return result, nil
}
