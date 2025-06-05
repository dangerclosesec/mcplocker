package mcps

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// MCPManager manages MCP providers and service connections
type MCPManager struct {
	registry          *ProviderRegistry
	serviceConnections map[string]*ServiceConnection // key: userID:provider:service
	mutex             sync.RWMutex
}

// NewMCPManager creates a new MCP manager
func NewMCPManager() *MCPManager {
	return &MCPManager{
		registry:           NewProviderRegistry(),
		serviceConnections: make(map[string]*ServiceConnection),
	}
}

// RegisterProvider registers a new MCP provider
func (m *MCPManager) RegisterProvider(provider MCPProvider) {
	m.registry.RegisterProvider(provider)
}

// GetProvider returns a provider by name
func (m *MCPManager) GetProvider(name string) (MCPProvider, bool) {
	return m.registry.GetProvider(name)
}

// GetAllProviders returns all registered providers
func (m *MCPManager) GetAllProviders() map[string]MCPProvider {
	return m.registry.GetProviders()
}

// GetAllServices returns all services across all providers
func (m *MCPManager) GetAllServices() map[string][]string {
	return m.registry.GetAllServices()
}

// GetAuthURL builds an OAuth authorization URL for a provider/service
func (m *MCPManager) GetAuthURL(providerName, service, userID string) (string, error) {
	provider, exists := m.registry.GetProvider(providerName)
	if !exists {
		return "", fmt.Errorf("provider %s not found", providerName)
	}
	
	// Create state with provider:service:userID to track the auth request
	state := fmt.Sprintf("%s:%s:%s", providerName, service, userID)
	
	return provider.GetAuthURL(service, state)
}

// HandleOAuthCallback processes OAuth callback and stores the connection
func (m *MCPManager) HandleOAuthCallback(providerName, service, userID, code string) error {
	provider, exists := m.registry.GetProvider(providerName)
	if !exists {
		return fmt.Errorf("provider %s not found", providerName)
	}
	
	// Exchange code for token
	ctx := context.Background()
	token, err := provider.ExchangeCodeForToken(ctx, service, code)
	if err != nil {
		return fmt.Errorf("failed to exchange code for token: %w", err)
	}
	
	// Store the service connection
	connection := &ServiceConnection{
		Provider:    providerName,
		Service:     service,
		UserID:      userID,
		Token:       token,
		ConnectedAt: time.Now().Format(time.RFC3339),
	}
	
	key := m.buildConnectionKey(userID, providerName, service)
	
	m.mutex.Lock()
	m.serviceConnections[key] = connection
	m.mutex.Unlock()
	
	return nil
}

// GetServiceConnection retrieves a service connection for a user
func (m *MCPManager) GetServiceConnection(userID, providerName, service string) (*ServiceConnection, bool) {
	key := m.buildConnectionKey(userID, providerName, service)
	
	m.mutex.RLock()
	connection, exists := m.serviceConnections[key]
	m.mutex.RUnlock()
	
	return connection, exists
}

// GetServiceConnectionByKey retrieves a service connection by key (for compatibility)
func (m *MCPManager) GetServiceConnectionByKey(key string) (*ServiceConnection, bool) {
	m.mutex.RLock()
	connection, exists := m.serviceConnections[key]
	m.mutex.RUnlock()
	
	return connection, exists
}

// GetUserConnections returns all service connections for a user
func (m *MCPManager) GetUserConnections(userID string) map[string]*ServiceConnection {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	connections := make(map[string]*ServiceConnection)
	prefix := userID + ":"
	
	for key, connection := range m.serviceConnections {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			connections[key] = connection
		}
	}
	
	return connections
}

// RefreshToken refreshes an expired token for a service connection
func (m *MCPManager) RefreshToken(userID, providerName, service string) error {
	provider, exists := m.registry.GetProvider(providerName)
	if !exists {
		return fmt.Errorf("provider %s not found", providerName)
	}
	
	key := m.buildConnectionKey(userID, providerName, service)
	
	m.mutex.Lock()
	connection, exists := m.serviceConnections[key]
	if !exists {
		m.mutex.Unlock()
		return fmt.Errorf("service connection not found")
	}
	
	// Refresh the token
	ctx := context.Background()
	newToken, err := provider.RefreshToken(ctx, service, connection.Token)
	if err != nil {
		m.mutex.Unlock()
		return fmt.Errorf("failed to refresh token: %w", err)
	}
	
	// Update the connection
	connection.Token = newToken
	connection.LastUsed = time.Now().Format(time.RFC3339)
	m.serviceConnections[key] = connection
	m.mutex.Unlock()
	
	return nil
}

// ValidateToken validates a token for a service connection
func (m *MCPManager) ValidateToken(userID, providerName, service string) error {
	provider, exists := m.registry.GetProvider(providerName)
	if !exists {
		return fmt.Errorf("provider %s not found", providerName)
	}
	
	connection, exists := m.GetServiceConnection(userID, providerName, service)
	if !exists {
		return fmt.Errorf("service connection not found")
	}
	
	ctx := context.Background()
	return provider.ValidateToken(ctx, service, connection.Token)
}

// RemoveServiceConnection removes a service connection
func (m *MCPManager) RemoveServiceConnection(userID, providerName, service string) {
	key := m.buildConnectionKey(userID, providerName, service)
	
	m.mutex.Lock()
	delete(m.serviceConnections, key)
	m.mutex.Unlock()
}

// GetOAuthConfig returns OAuth config for a provider/service
func (m *MCPManager) GetOAuthConfig(providerName, service string) (*oauth2.Config, error) {
	provider, exists := m.registry.GetProvider(providerName)
	if !exists {
		return nil, fmt.Errorf("provider %s not found", providerName)
	}
	
	return provider.GetOAuthConfig(service)
}

// buildConnectionKey builds a consistent key for service connections
func (m *MCPManager) buildConnectionKey(userID, provider, service string) string {
	return fmt.Sprintf("%s:%s:%s", userID, provider, service)
}

// buildOldConnectionKey builds the old-style key for backwards compatibility
func (m *MCPManager) buildOldConnectionKey(userID, service string) string {
	return fmt.Sprintf("%s:%s", userID, service)
}