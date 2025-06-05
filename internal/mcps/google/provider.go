package google

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/dangerclosesec/mcplocker/internal/config"
	"golang.org/x/oauth2"
)

// GoogleProvider implements the MCPProvider interface for Google services
type GoogleProvider struct {
	config *config.GoogleConfig
}

// NewGoogleProvider creates a new Google MCP provider
func NewGoogleProvider() (*GoogleProvider, error) {
	googleConfig, err := config.LoadGoogleConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Google config: %w", err)
	}
	
	return &GoogleProvider{
		config: googleConfig,
	}, nil
}

// GetName returns the provider name
func (g *GoogleProvider) GetName() string {
	return "google"
}

// GetServices returns available Google services
func (g *GoogleProvider) GetServices() []string {
	return []string{"calendar", "gmail", "drive"}
}

// GetOAuthConfig returns OAuth2 configuration for a Google service
func (g *GoogleProvider) GetOAuthConfig(service string) (*oauth2.Config, error) {
	scopes := g.getScopesForService(service)
	if len(scopes) == 0 {
		return nil, fmt.Errorf("unsupported service: %s", service)
	}
	
	return &oauth2.Config{
		ClientID:     g.config.GetClientID(),
		ClientSecret: g.config.GetClientSecret(),
		RedirectURL:  g.config.GetRedirectURI(),
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  g.config.GetAuthURI(),
			TokenURL: g.config.GetTokenURI(),
		},
	}, nil
}

// GetAuthURL builds the OAuth authorization URL for a Google service
func (g *GoogleProvider) GetAuthURL(service, state string) (string, error) {
	scopes := g.getScopesForService(service)
	if len(scopes) == 0 {
		return "", fmt.Errorf("unsupported service: %s", service)
	}
	
	params := url.Values{}
	params.Add("client_id", g.config.GetClientID())
	params.Add("redirect_uri", g.config.GetRedirectURI())
	params.Add("scope", strings.Join(scopes, " "))
	params.Add("response_type", "code")
	params.Add("access_type", "offline")
	params.Add("prompt", "consent")
	params.Add("state", state) // Use state to track service and other info
	
	return g.config.GetAuthURI() + "?" + params.Encode(), nil
}

// ExchangeCodeForToken exchanges authorization code for Google tokens
func (g *GoogleProvider) ExchangeCodeForToken(ctx context.Context, service, code string) (*oauth2.Token, error) {
	oauthConfig, err := g.GetOAuthConfig(service)
	if err != nil {
		return nil, err
	}
	
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	
	return token, nil
}

// ValidateToken checks if a Google token is still valid
func (g *GoogleProvider) ValidateToken(ctx context.Context, service string, token *oauth2.Token) error {
	if !token.Valid() {
		return fmt.Errorf("token is expired")
	}
	
	// TODO: Make a test API call to verify token is actually valid
	// For now, just check expiration
	return nil
}

// RefreshToken refreshes an expired Google token
func (g *GoogleProvider) RefreshToken(ctx context.Context, service string, token *oauth2.Token) (*oauth2.Token, error) {
	oauthConfig, err := g.GetOAuthConfig(service)
	if err != nil {
		return nil, err
	}
	
	tokenSource := oauthConfig.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	
	return newToken, nil
}

// getScopesForService returns the required OAuth scopes for a Google service
func (g *GoogleProvider) getScopesForService(service string) []string {
	switch service {
	case "calendar":
		return []string{
			"https://www.googleapis.com/auth/calendar",
			"https://www.googleapis.com/auth/calendar.events",
		}
	case "gmail":
		return []string{
			"https://www.googleapis.com/auth/gmail.send",
			"https://www.googleapis.com/auth/gmail.readonly",
		}
	case "drive":
		return []string{
			"https://www.googleapis.com/auth/drive",
			"https://www.googleapis.com/auth/drive.file",
		}
	default:
		return nil
	}
}