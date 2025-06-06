package mcps

import (
	"context"

	"golang.org/x/oauth2"
)

// MCPProvider represents a provider (Google, GitHub, Slack, etc.)
type MCPProvider interface {
	// GetName returns the provider name (e.g., "google", "github")
	GetName() string

	// GetServices returns available services for this provider
	GetServices() []string

	// GetOAuthConfig returns OAuth2 configuration for a service
	GetOAuthConfig(service string) (*oauth2.Config, error)

	// GetAuthURL builds the OAuth authorization URL for a service
	GetAuthURL(service, state string) (string, error)

	// ExchangeCodeForToken exchanges authorization code for tokens
	ExchangeCodeForToken(ctx context.Context, service, code string) (*oauth2.Token, error)

	// ValidateToken checks if a token is still valid
	ValidateToken(ctx context.Context, service string, token *oauth2.Token) error

	// RefreshToken refreshes an expired token
	RefreshToken(ctx context.Context, service string, token *oauth2.Token) (*oauth2.Token, error)
}

// ServiceConnection represents an authenticated connection to a service
type ServiceConnection struct {
	Provider    string        `json:"provider"`
	Service     string        `json:"service"`
	UserID      string        `json:"user_id"`
	Token       *oauth2.Token `json:"token"`
	ConnectedAt string        `json:"connected_at"`
	LastUsed    string        `json:"last_used,omitempty"`
}

// ProviderRegistry manages all registered MCP providers
type ProviderRegistry struct {
	providers map[string]MCPProvider
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]MCPProvider),
	}
}

// RegisterProvider registers a new MCP provider
func (r *ProviderRegistry) RegisterProvider(provider MCPProvider) {
	r.providers[provider.GetName()] = provider
}

// GetProvider returns a provider by name
func (r *ProviderRegistry) GetProvider(name string) (MCPProvider, bool) {
	provider, exists := r.providers[name]
	return provider, exists
}

// GetProviders returns all registered providers
func (r *ProviderRegistry) GetProviders() map[string]MCPProvider {
	return r.providers
}

// GetAllServices returns all services across all providers
func (r *ProviderRegistry) GetAllServices() map[string][]string {
	services := make(map[string][]string)
	for name, provider := range r.providers {
		services[name] = provider.GetServices()
	}
	return services
}
