package github

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

// GitHubProvider implements the MCPProvider interface for GitHub services
type GitHubProvider struct {
	clientID     string
	clientSecret string
	redirectURI  string
}

// NewGitHubProvider creates a new GitHub MCP provider
func NewGitHubProvider(clientID, clientSecret, redirectURI string) *GitHubProvider {
	return &GitHubProvider{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURI:  redirectURI,
	}
}

// GetName returns the provider name
func (g *GitHubProvider) GetName() string {
	return "github"
}

// GetServices returns available GitHub services
func (g *GitHubProvider) GetServices() []string {
	return []string{"repos", "issues", "actions"}
}

// GetOAuthConfig returns OAuth2 configuration for a GitHub service
func (g *GitHubProvider) GetOAuthConfig(service string) (*oauth2.Config, error) {
	scopes := g.getScopesForService(service)
	if len(scopes) == 0 {
		return nil, fmt.Errorf("unsupported service: %s", service)
	}
	
	return &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecret,
		RedirectURL:  g.redirectURI,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}, nil
}

// GetAuthURL builds the OAuth authorization URL for a GitHub service
func (g *GitHubProvider) GetAuthURL(service, state string) (string, error) {
	scopes := g.getScopesForService(service)
	if len(scopes) == 0 {
		return "", fmt.Errorf("unsupported service: %s", service)
	}
	
	params := url.Values{}
	params.Add("client_id", g.clientID)
	params.Add("redirect_uri", g.redirectURI)
	params.Add("scope", strings.Join(scopes, " "))
	params.Add("response_type", "code")
	params.Add("state", state) // Use state to track service and other info
	
	return "https://github.com/login/oauth/authorize?" + params.Encode(), nil
}

// ExchangeCodeForToken exchanges authorization code for GitHub tokens
func (g *GitHubProvider) ExchangeCodeForToken(ctx context.Context, service, code string) (*oauth2.Token, error) {
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

// ValidateToken checks if a GitHub token is still valid
func (g *GitHubProvider) ValidateToken(ctx context.Context, service string, token *oauth2.Token) error {
	if !token.Valid() {
		return fmt.Errorf("token is expired")
	}
	
	// TODO: Make a test API call to GitHub to verify token is actually valid
	// For now, GitHub tokens don't have expiration by default
	return nil
}

// RefreshToken refreshes an expired GitHub token
func (g *GitHubProvider) RefreshToken(ctx context.Context, service string, token *oauth2.Token) (*oauth2.Token, error) {
	// GitHub OAuth tokens typically don't expire unless explicitly revoked
	// So we just return the same token
	return token, nil
}

// getScopesForService returns the required OAuth scopes for a GitHub service
func (g *GitHubProvider) getScopesForService(service string) []string {
	switch service {
	case "repos":
		return []string{
			"repo", // Full control of private repositories
			"read:user", // Read user profile data
		}
	case "issues":
		return []string{
			"repo", // Access to repository issues
			"read:user", // Read user profile data
		}
	case "actions":
		return []string{
			"repo", // Access to repository actions
			"workflow", // Write access to GitHub Actions workflows
			"read:user", // Read user profile data
		}
	default:
		return nil
	}
}