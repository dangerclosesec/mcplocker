package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// GoogleConfig represents Google OAuth configuration
type GoogleConfig struct {
	Web struct {
		ClientID                string   `json:"client_id"`
		ProjectID               string   `json:"project_id"`
		AuthURI                 string   `json:"auth_uri"`
		TokenURI                string   `json:"token_uri"`
		AuthProviderX509CertURL string   `json:"auth_provider_x509_cert_url"`
		ClientSecret            string   `json:"client_secret"`
		RedirectURIs            []string `json:"redirect_uris"`
	} `json:"web"`
}

// LoadGoogleConfig loads Google OAuth configuration from .secrets/client_secrets.json
func LoadGoogleConfig() (*GoogleConfig, error) {
	data, err := os.ReadFile(".secrets/client_secrets.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read Google client secrets: %w", err)
	}

	var config GoogleConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse Google client secrets: %w", err)
	}

	return &config, nil
}

// GetClientID returns the Google OAuth client ID
func (g *GoogleConfig) GetClientID() string {
	return g.Web.ClientID
}

// GetClientSecret returns the Google OAuth client secret
func (g *GoogleConfig) GetClientSecret() string {
	return g.Web.ClientSecret
}

// GetAuthURI returns the Google OAuth authorization URI
func (g *GoogleConfig) GetAuthURI() string {
	return g.Web.AuthURI
}

// GetTokenURI returns the Google OAuth token URI
func (g *GoogleConfig) GetTokenURI() string {
	return g.Web.TokenURI
}

// GetRedirectURI returns the appropriate redirect URI for localhost
func (g *GoogleConfig) GetRedirectURI() string {
	for _, uri := range g.Web.RedirectURIs {
		if uri == "http://localhost:38741/api/auth/callback/google" {
			return uri
		}
	}
	// Fallback to first redirect URI if localhost not found
	if len(g.Web.RedirectURIs) > 0 {
		return g.Web.RedirectURIs[0]
	}
	return ""
}
