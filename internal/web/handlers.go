package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/dangerclosesec/mcplocker/internal/config"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// OAuthConfig holds OAuth configuration for different providers
type OAuthConfig struct {
	Google *oauth2.Config
	Okta   *oauth2.Config
	GitHub *oauth2.Config
}

// ServiceConnection represents a connected service with token and user info
type ServiceConnection struct {
	Token     *oauth2.Token
	UserEmail string
	UserID    string
}

// WebHandlers contains all web route handlers
type WebHandlers struct {
	oauth         *OAuthConfig
	sessions      map[string]*User               // Simple in-memory session store - use Redis in production
	serviceTokens map[string]*ServiceConnection // Service-specific connections keyed by "userID:service"
	tokenManager  *TokenManager                 // API token manager
}

// NewWebHandlers creates a new instance of web handlers
func NewWebHandlers() *WebHandlers {
	// Load Google OAuth config from .secrets file
	googleSecrets, err := config.LoadGoogleConfig()
	if err != nil {
		log.Printf("Failed to load Google config: %v", err)
		// Return handlers with nil Google config - auth will be disabled
		return &WebHandlers{
			oauth: &OAuthConfig{
				Google: nil,
			},
			sessions: make(map[string]*User),
		}
	}

	googleConfig := &oauth2.Config{
		ClientID:     googleSecrets.GetClientID(),
		ClientSecret: googleSecrets.GetClientSecret(),
		RedirectURL:  "http://localhost:38741/api/auth/callback/google",
		Scopes: []string{
			"openid",
			"profile",
			"email",
		},
		Endpoint: google.Endpoint,
	}

	// Initialize token manager
	tokenManager, err := NewTokenManager()
	if err != nil {
		log.Printf("Failed to initialize token manager: %v", err)
		// Return handlers with nil token manager - token features will be disabled
		return &WebHandlers{
			oauth: &OAuthConfig{
				Google: googleConfig,
			},
			sessions:      make(map[string]*User),
			serviceTokens: make(map[string]*ServiceConnection),
		}
	}

	handlers := &WebHandlers{
		oauth: &OAuthConfig{
			Google: googleConfig,
		},
		sessions:      make(map[string]*User),
		serviceTokens: make(map[string]*ServiceConnection),
		tokenManager:  tokenManager,
	}
	
	// Load existing service tokens from persistent storage
	if err := handlers.LoadServiceTokens(); err != nil {
		log.Printf("Warning: Failed to load service tokens: %v", err)
	}
	
	return handlers
}

// generateSessionToken generates a secure random session token
func generateSessionToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// getUser retrieves user from session cookie
func (h *WebHandlers) getUser(r *http.Request) *User {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}
	return h.sessions[cookie.Value]
}

// GetUser is the public method to retrieve user from session cookie
func (h *WebHandlers) GetUser(r *http.Request) *User {
	return h.getUser(r)
}

// GetServiceConnection retrieves a service connection by token key
func (h *WebHandlers) GetServiceConnection(tokenKey string) (*ServiceConnection, bool) {
	connection, exists := h.serviceTokens[tokenKey]
	return connection, exists
}

// isServiceConnected checks if a user has a valid token for a specific service
func (h *WebHandlers) isServiceConnected(userID, service string) bool {
	tokenKey := userID + ":" + service
	connection, exists := h.serviceTokens[tokenKey]
	if !exists {
		return false
	}
	
	// Check if token is still valid (not expired)
	return connection.Token != nil && connection.Token.Valid()
}

// getServiceEmail returns the email address for a connected service
func (h *WebHandlers) getServiceEmail(userID, service string) string {
	tokenKey := userID + ":" + service
	connection, exists := h.serviceTokens[tokenKey]
	if !exists {
		return ""
	}
	
	return connection.UserEmail
}

// requireAuth middleware ensures user is authenticated
func (h *WebHandlers) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.getUser(r)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requireAuthMiddleware creates a middleware compatible with chi.Router.Use
func (h *WebHandlers) requireAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := h.getUser(r)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HandleHome serves the home page (redirects to dashboard if authenticated)
func (h *WebHandlers) HandleHome(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r)
	if user != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleLogin serves the login page
func (h *WebHandlers) HandleLogin(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r)
	if user != nil {
		// Check if there's a return_to parameter for after login
		returnTo := r.URL.Query().Get("return_to")
		if returnTo != "" {
			http.Redirect(w, r, returnTo, http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		}
		return
	}

	data := PageData{
		Title: "Sign In",
		User:  nil,
	}

	RenderTemplate(w, "login.html", data)
}

// HandleLogout logs out the user
func (h *WebHandlers) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		delete(h.sessions, cookie.Value)
	}
	
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	})
	
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HandleDashboard serves the main dashboard
func (h *WebHandlers) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r)
	
	// Calculate actual service counts
	connectedServices := 0
	activeTokens := 0
	
	if user != nil {
		// Count connected services
		services := []string{"gmail", "calendar", "drive"}
		for _, service := range services {
			if h.isServiceConnected(user.ID, service) {
				connectedServices++
			}
		}
		
		// For now, activeTokens is same as connectedServices
		// In the future, this could include CLI tokens, etc.
		activeTokens = connectedServices
	}
	
	data := struct {
		PageData
		ConnectedServices int
		ActiveTokens      int
	}{
		PageData: PageData{
			Title: "Dashboard",
			User:  user,
		},
		ConnectedServices: connectedServices,
		ActiveTokens:      activeTokens,
	}
	
	RenderTemplate(w, "dashboard.html", data)
}

// HandleServices serves the services management page
func (h *WebHandlers) HandleServices(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r)
	
	// Create services data structure for template
	servicesData := struct {
		Gmail struct {
			Connected bool
			Email     string
		}
		Calendar struct {
			Connected bool
			Email     string
		}
		Drive struct {
			Connected bool
			Email     string
		}
		GitHubRepos struct {
			Connected bool
			Username  string
		}
		GitHubIssues struct {
			Connected bool
			Username  string
		}
		ErrorMessage string
	}{}
	
	// Check for error message from OAuth callback
	if errorMsg := r.URL.Query().Get("error"); errorMsg != "" {
		servicesData.ErrorMessage = errorMsg
	}
	
	// Check actual service connection status from stored tokens
	if user != nil {
		servicesData.Gmail.Connected = h.isServiceConnected(user.ID, "gmail")
		servicesData.Gmail.Email = h.getServiceEmail(user.ID, "gmail")
		
		servicesData.Calendar.Connected = h.isServiceConnected(user.ID, "calendar")
		servicesData.Calendar.Email = h.getServiceEmail(user.ID, "calendar")
		
		servicesData.Drive.Connected = h.isServiceConnected(user.ID, "drive")
		servicesData.Drive.Email = h.getServiceEmail(user.ID, "drive")
		
		// Check GitHub services using the new key format
		servicesData.GitHubRepos.Connected = h.isServiceConnected(user.ID, "github:repos")
		servicesData.GitHubRepos.Username = h.getServiceEmail(user.ID, "github:repos")
		
		servicesData.GitHubIssues.Connected = h.isServiceConnected(user.ID, "github:issues")
		servicesData.GitHubIssues.Username = h.getServiceEmail(user.ID, "github:issues")
	}
	
	data := struct {
		PageData
		Services struct {
			Gmail struct {
				Connected bool
				Email     string
			}
			Calendar struct {
				Connected bool
				Email     string
			}
			Drive struct {
				Connected bool
				Email     string
			}
			GitHubRepos struct {
				Connected bool
				Username  string
			}
			GitHubIssues struct {
				Connected bool
				Username  string
			}
		}
		ErrorMessage string
	}{
		PageData: PageData{
			Title: "Connected Services",
			User:  user,
		},
		Services: struct {
			Gmail struct {
				Connected bool
				Email     string
			}
			Calendar struct {
				Connected bool
				Email     string
			}
			Drive struct {
				Connected bool
				Email     string
			}
			GitHubRepos struct {
				Connected bool
				Username  string
			}
			GitHubIssues struct {
				Connected bool
				Username  string
			}
		}{
			Gmail:        servicesData.Gmail,
			Calendar:     servicesData.Calendar,
			Drive:        servicesData.Drive,
			GitHubRepos:  servicesData.GitHubRepos,
			GitHubIssues: servicesData.GitHubIssues,
		},
		ErrorMessage: servicesData.ErrorMessage,
	}
	
	RenderTemplate(w, "services.html", data)
}

// HandleTokens serves the API tokens management page
func (h *WebHandlers) HandleTokens(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r)
	
	// Get user's tokens
	var tokens []*APIToken
	if h.tokenManager != nil && user != nil {
		tokens = h.tokenManager.GetUserTokens(user.ID)
	}
	
	data := struct {
		PageData
		Tokens []*APIToken
	}{
		PageData: PageData{
			Title: "API Tokens",
			User:  user,
		},
		Tokens: tokens,
	}
	
	RenderTemplate(w, "tokens.html", data)
}

// HandleGoogleAuth initiates Google OAuth flow
func (h *WebHandlers) HandleGoogleAuth(w http.ResponseWriter, r *http.Request) {
	if h.oauth.Google == nil {
		http.Error(w, "Google OAuth not configured", http.StatusInternalServerError)
		return
	}

	state := generateSessionToken()
	url := h.oauth.Google.AuthCodeURL(state, oauth2.AccessTypeOffline)
	
	// Store state for validation (use proper session store in production)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	})
	
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleGoogleCallback handles Google OAuth callback
func (h *WebHandlers) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if h.oauth.Google == nil {
		http.Error(w, "Google OAuth not configured", http.StatusInternalServerError)
		return
	}

	// Check for OAuth errors (user cancelled, access denied, etc.)
	if errorParam := r.URL.Query().Get("error"); errorParam != "" {
		errorDescription := r.URL.Query().Get("error_description")
		urlState := r.URL.Query().Get("state")
		
		// Extract service from state if present (format: "service:token" or just "token")
		var service string
		if strings.Contains(urlState, ":") {
			parts := strings.SplitN(urlState, ":", 2)
			service = parts[0]
		}
		
		log.Printf("OAuth error for service %s: %s - %s", service, errorParam, errorDescription)
		
		// Clear state cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
		
		// Handle different error types
		var message string
		switch errorParam {
		case "access_denied":
			if service != "" {
				serviceName := strings.ToUpper(service[:1]) + service[1:] // Simple title case
				message = fmt.Sprintf("Authorization was cancelled. %s service was not connected.", serviceName)
			} else {
				message = "Authorization was cancelled. You were not signed in."
			}
		default:
			if service != "" {
				serviceName := strings.ToUpper(service[:1]) + service[1:] // Simple title case
				message = fmt.Sprintf("Authorization failed for %s service. Please try again.", serviceName)
			} else {
				message = "Authorization failed. Please try again."
			}
		}
		
		// Redirect with error message
		if service != "" {
			// For service-specific auth, redirect to services page with error
			http.Redirect(w, r, "/services?error="+url.QueryEscape(message), http.StatusSeeOther)
		} else {
			// For general auth, redirect to login page with error
			http.Redirect(w, r, "/login?error="+url.QueryEscape(message), http.StatusSeeOther)
		}
		return
	}

	// Get state from URL and cookie
	urlState := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != urlState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Extract service from state if present (format: "service:token" or just "token")
	var service string
	if strings.Contains(urlState, ":") {
		parts := strings.SplitN(urlState, ":", 2)
		service = parts[0]
	}
	
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	
	// Exchange authorization code for token
	code := r.URL.Query().Get("code")
	token, err := h.oauth.Google.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		log.Printf("Token exchange error: %v", err)
		return
	}

	// If this is a service-specific auth, store the token and redirect
	if service != "" {
		// Get current user session to associate token with user
		user := h.getUser(r)
		if user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}
		
		// Get Google user info to extract email for this service connection
		client := h.oauth.Google.Client(context.Background(), token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			log.Printf("Failed to get user info for service %s: %v", service, err)
			// Still store the connection without email
		}
		
		var googleEmail string
		if resp != nil {
			defer resp.Body.Close()
			var userInfo struct {
				Email string `json:"email"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&userInfo); err == nil {
				googleEmail = userInfo.Email
			}
		}
		
		// Store service connection
		tokenKey := user.ID + ":" + service
		h.serviceTokens[tokenKey] = &ServiceConnection{
			Token:     token,
			UserEmail: googleEmail,
			UserID:    user.ID,
		}
		
		// Save tokens to persistent storage
		if err := h.SaveServiceTokens(); err != nil {
			log.Printf("Warning: Failed to save service tokens: %v", err)
		}
		
		// Notify about tool changes
		if GlobalToolChangeNotifier != nil {
			GlobalToolChangeNotifier.NotifyToolChange(user.ID)
		}
		
		log.Printf("Stored %s token for user %s (Google account: %s)", service, user.Email, googleEmail)
		http.Redirect(w, r, "/services", http.StatusSeeOther)
		return
	}
	
	// For general auth flow, continue with user info retrieval
	client := h.oauth.Google.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		log.Printf("User info error: %v", err)
		return
	}
	defer resp.Body.Close()
	
	var userInfo struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		log.Printf("User info decode error: %v", err)
		return
	}
	
	// Create user session
	user := &User{
		ID:      userInfo.ID,
		Email:   userInfo.Email,
		Name:    userInfo.Name,
		Picture: userInfo.Picture,
	}
	
	sessionToken := generateSessionToken()
	h.sessions[sessionToken] = user
	
	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	})
	
	// Check for return_to parameter in the original request
	// This might be stored in a session or passed through state parameter
	// For now, let's check if there's a return_to cookie or state parameter
	returnTo := ""
	if returnToCookie, err := r.Cookie("return_to"); err == nil {
		returnTo = returnToCookie.Value
		// Clear the return_to cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "return_to",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}

	// Redirect based on priority: return_to > service-specific > general auth
	if returnTo != "" {
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
	} else if service != "" {
		// Service-specific authentication - redirect to services page
		http.Redirect(w, r, "/services", http.StatusSeeOther)
	} else {
		// General authentication - redirect to dashboard
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

// HandleServiceAuth creates a service-specific OAuth handler
func (h *WebHandlers) HandleServiceAuth(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.oauth.Google == nil {
			http.Error(w, "Google OAuth not configured", http.StatusInternalServerError)
			return
		}

		// Create a new OAuth config with service-specific scopes
		googleSecrets, err := config.LoadGoogleConfig()
		if err != nil {
			http.Error(w, "Failed to load Google configuration", http.StatusInternalServerError)
			return
		}

		// Define scopes based on the service
		var scopes []string
		switch service {
		case "gmail":
			scopes = []string{
				"https://www.googleapis.com/auth/gmail.send",
				"https://www.googleapis.com/auth/gmail.readonly",
				"openid",
				"profile",
				"email",
			}
		case "calendar":
			scopes = []string{
				"https://www.googleapis.com/auth/calendar",
				"https://www.googleapis.com/auth/calendar.events",
				"openid",
				"profile",
				"email",
			}
		case "drive":
			scopes = []string{
				"https://www.googleapis.com/auth/drive",
				"https://www.googleapis.com/auth/drive.file",
				"openid",
				"profile",
				"email",
			}
		default:
			http.Error(w, "Unsupported service", http.StatusBadRequest)
			return
		}

		// Create service-specific OAuth config
		serviceOAuthConfig := &oauth2.Config{
			ClientID:     googleSecrets.GetClientID(),
			ClientSecret: googleSecrets.GetClientSecret(),
			RedirectURL:  "http://localhost:38741/api/auth/callback/google",
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		}

		// Generate state token that includes the service name
		state := service + ":" + generateSessionToken()
		url := serviceOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
		
		// Store state for validation
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   300, // 5 minutes
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
		})
		
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// RegisterRoutes registers all web routes
func (h *WebHandlers) RegisterRoutes(r chi.Router) {
	// Public routes
	r.Get("/", h.HandleHome)
	r.Get("/login", h.HandleLogin)
	r.Get("/logout", h.HandleLogout)
	
	// OAuth routes
	r.Get("/auth/google", h.HandleGoogleAuth)
	r.Get("/api/auth/callback/google", h.HandleGoogleCallback)
	
	// Service-specific OAuth routes
	r.Get("/auth/service/gmail", h.HandleServiceAuth("gmail"))
	r.Get("/auth/service/calendar", h.HandleServiceAuth("calendar"))
	r.Get("/auth/service/drive", h.HandleServiceAuth("drive"))
	
	// GitHub OAuth routes
	r.Get("/auth/service/github/repos", h.HandleGitHubServiceAuth("repos"))
	r.Get("/auth/service/github/issues", h.HandleGitHubServiceAuth("issues"))
	r.Get("/api/auth/callback/github", h.HandleGitHubCallback)
	
	// Protected routes
	r.Group(func(r chi.Router) {
		r.Get("/dashboard", h.requireAuth(h.HandleDashboard))
		r.Get("/services", h.requireAuth(h.HandleServices))
		r.Get("/tokens", h.requireAuth(h.HandleTokens))
	})

	// API routes for token management
	r.Route("/api/tokens", func(r chi.Router) {
		r.Use(h.requireAuthMiddleware) // Require web session authentication
		r.Post("/", h.HandleCreateToken)
		r.Delete("/{tokenId}", h.HandleRevokeToken)
	})
}

// HandleGitHubServiceAuth creates a GitHub service-specific OAuth handler
func (h *WebHandlers) HandleGitHubServiceAuth(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if GitHub OAuth is configured via environment variables
		clientID := os.Getenv("GITHUB_CLIENT_ID")
		clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
		
		if clientID == "" || clientSecret == "" {
			http.Error(w, "GitHub OAuth not configured. Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET environment variables.", http.StatusInternalServerError)
			return
		}

		// Define scopes based on the service
		var scopes []string
		switch service {
		case "repos":
			scopes = []string{
				"repo",       // Full control of private repositories
				"read:user",  // Read user profile data
			}
		case "issues":
			scopes = []string{
				"repo",       // Access to repository issues
				"read:user",  // Read user profile data
			}
		default:
			http.Error(w, "Unsupported GitHub service", http.StatusBadRequest)
			return
		}

		// Create GitHub OAuth config
		githubOAuthConfig := &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  "http://localhost:38741/api/auth/callback/github",
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
		}

		// Generate state token that includes the service name
		state := "github:" + service + ":" + generateSessionToken()
		url := githubOAuthConfig.AuthCodeURL(state)
		
		// Store state for validation
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   300, // 5 minutes
			HttpOnly: true,
			Secure:   false, // Set to true in production with HTTPS
		})
		
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// HandleGitHubCallback handles GitHub OAuth callback
func (h *WebHandlers) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	// Check for OAuth errors
	if errorParam := r.URL.Query().Get("error"); errorParam != "" {
		errorDescription := r.URL.Query().Get("error_description")
		urlState := r.URL.Query().Get("state")
		
		// Extract service from state if present (format: "github:service:token")
		var service string
		if strings.HasPrefix(urlState, "github:") {
			parts := strings.SplitN(urlState, ":", 3)
			if len(parts) >= 2 {
				service = parts[1]
			}
		}
		
		log.Printf("GitHub OAuth error for service %s: %s - %s", service, errorParam, errorDescription)
		
		// Clear state cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
		
		// Handle different error types
		var message string
		switch errorParam {
		case "access_denied":
			if service != "" {
				serviceName := strings.ToUpper(service[:1]) + service[1:] // Simple title case
				message = fmt.Sprintf("GitHub authorization was cancelled. %s service was not connected.", serviceName)
			} else {
				message = "GitHub authorization was cancelled."
			}
		default:
			if service != "" {
				serviceName := strings.ToUpper(service[:1]) + service[1:] // Simple title case
				message = fmt.Sprintf("GitHub authorization failed for %s service. Please try again.", serviceName)
			} else {
				message = "GitHub authorization failed. Please try again."
			}
		}
		
		// Redirect with error message
		http.Redirect(w, r, "/services?error="+url.QueryEscape(message), http.StatusSeeOther)
		return
	}

	// Get state from URL and cookie
	urlState := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != urlState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Extract service from state (format: "github:service:token")
	var service string
	if strings.HasPrefix(urlState, "github:") {
		parts := strings.SplitN(urlState, ":", 3)
		if len(parts) >= 2 {
			service = parts[1]
		}
	}
	
	if service == "" {
		http.Error(w, "Invalid state format", http.StatusBadRequest)
		return
	}
	
	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Get current user session to associate token with user
	user := h.getUser(r)
	if user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}
	
	// Check if GitHub OAuth is configured
	clientID := os.Getenv("GITHUB_CLIENT_ID")
	clientSecret := os.Getenv("GITHUB_CLIENT_SECRET")
	
	if clientID == "" || clientSecret == "" {
		http.Error(w, "GitHub OAuth not configured", http.StatusInternalServerError)
		return
	}

	// Create GitHub OAuth config
	githubOAuthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:38741/api/auth/callback/github",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
	
	// Exchange authorization code for token
	code := r.URL.Query().Get("code")
	token, err := githubOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		log.Printf("GitHub token exchange error: %v", err)
		return
	}

	// Get GitHub user info to extract username
	client := githubOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		log.Printf("Failed to get GitHub user info for service %s: %v", service, err)
		// Still store the connection without username
	}
	
	var githubUsername string
	if resp != nil {
		defer resp.Body.Close()
		var userInfo struct {
			Login string `json:"login"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err == nil {
			githubUsername = userInfo.Login
		}
	}
	
	// Store service connection with new key format
	tokenKey := user.ID + ":github:" + service
	h.serviceTokens[tokenKey] = &ServiceConnection{
		Token:     token,
		UserEmail: githubUsername, // Using UserEmail field to store GitHub username
		UserID:    user.ID,
	}
	
	// Save tokens to persistent storage
	if err := h.SaveServiceTokens(); err != nil {
		log.Printf("Warning: Failed to save service tokens: %v", err)
	}
	
	// Notify about tool changes
	if GlobalToolChangeNotifier != nil {
		GlobalToolChangeNotifier.NotifyToolChange(user.ID)
	}
	
	log.Printf("Stored GitHub %s token for user %s (GitHub account: %s)", service, user.Email, githubUsername)
	http.Redirect(w, r, "/services", http.StatusSeeOther)
}

// HandleCreateToken creates a new API token
func (h *WebHandlers) HandleCreateToken(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r)
	if user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	if h.tokenManager == nil {
		http.Error(w, "Token management not available", http.StatusInternalServerError)
		return
	}

	var req TokenCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Name == "" {
		http.Error(w, "Token name is required", http.StatusBadRequest)
		return
	}

	// Set default permissions if none provided
	if len(req.Permissions) == 0 {
		req.Permissions = []string{"api:read", "api:write", "tools:execute"}
	}

	// Create token
	tokenResp, err := h.tokenManager.CreateToken(user.ID, req)
	if err != nil {
		log.Printf("Failed to create token for user %s: %v", user.ID, err)
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Log token creation for audit
	log.Printf("Created API token %s for user %s (name: %s)", tokenResp.ID, user.Email, req.Name)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// HandleRevokeToken revokes an API token
func (h *WebHandlers) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	user := h.getUser(r)
	if user == nil {
		http.Error(w, "User not authenticated", http.StatusUnauthorized)
		return
	}

	if h.tokenManager == nil {
		http.Error(w, "Token management not available", http.StatusInternalServerError)
		return
	}

	tokenID := chi.URLParam(r, "tokenId")
	if tokenID == "" {
		http.Error(w, "Token ID is required", http.StatusBadRequest)
		return
	}

	// Revoke token
	if err := h.tokenManager.RevokeToken(user.ID, tokenID); err != nil {
		log.Printf("Failed to revoke token %s for user %s: %v", tokenID, user.ID, err)
		http.Error(w, "Failed to revoke token", http.StatusInternalServerError)
		return
	}

	// Log token revocation for audit
	log.Printf("Revoked API token %s for user %s", tokenID, user.Email)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Token revoked successfully",
	})
}

// ValidateAPIToken validates an API token and returns the associated user info
func (h *WebHandlers) ValidateAPIToken(token string) (*APIToken, error) {
	if h.tokenManager == nil {
		return nil, fmt.Errorf("token management not available")
	}
	
	return h.tokenManager.ValidateToken(token)
}