package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/oauth2"
)

// PersistentServiceConnection represents a service connection for persistence
type PersistentServiceConnection struct {
	Token     *oauth2.Token `json:"token"`
	UserEmail string        `json:"user_email"`
	UserID    string        `json:"user_id"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// getTokensFilePath returns the path to the tokens file
func getTokensFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	
	configDir := filepath.Join(homeDir, ".config", "mcplocker")
	tokensFile := filepath.Join(configDir, "service_tokens.json")
	
	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}
	
	return tokensFile, nil
}

// SaveServiceTokens saves service tokens to persistent storage
func (h *WebHandlers) SaveServiceTokens() error {
	tokensFile, err := getTokensFilePath()
	if err != nil {
		return err
	}
	
	// Convert service tokens to persistent format
	persistentTokens := make(map[string]PersistentServiceConnection)
	for key, connection := range h.serviceTokens {
		persistentTokens[key] = PersistentServiceConnection{
			Token:     connection.Token,
			UserEmail: connection.UserEmail,
			UserID:    connection.UserID,
			CreatedAt: time.Now(), // We don't have original creation time, use current
			UpdatedAt: time.Now(),
		}
	}
	
	// Write to file
	data, err := json.MarshalIndent(persistentTokens, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}
	
	if err := os.WriteFile(tokensFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write tokens file: %w", err)
	}
	
	return nil
}

// LoadServiceTokens loads service tokens from persistent storage
func (h *WebHandlers) LoadServiceTokens() error {
	tokensFile, err := getTokensFilePath()
	if err != nil {
		return err
	}
	
	// Check if file exists
	if _, err := os.Stat(tokensFile); os.IsNotExist(err) {
		// File doesn't exist, that's okay - start with empty tokens
		return nil
	}
	
	// Read file
	data, err := os.ReadFile(tokensFile)
	if err != nil {
		return fmt.Errorf("failed to read tokens file: %w", err)
	}
	
	// Parse JSON
	var persistentTokens map[string]PersistentServiceConnection
	if err := json.Unmarshal(data, &persistentTokens); err != nil {
		return fmt.Errorf("failed to unmarshal tokens: %w", err)
	}
	
	// Convert back to service connections and validate tokens
	for key, persistentConnection := range persistentTokens {
		// Check if token is still valid (not expired)
		if persistentConnection.Token != nil && persistentConnection.Token.Valid() {
			h.serviceTokens[key] = &ServiceConnection{
				Token:     persistentConnection.Token,
				UserEmail: persistentConnection.UserEmail,
				UserID:    persistentConnection.UserID,
			}
		}
		// If token is expired, we skip it (effectively removing it)
	}
	
	return nil
}

// ClearExpiredTokens removes expired tokens from both memory and persistent storage
func (h *WebHandlers) ClearExpiredTokens() error {
	// Remove expired tokens from memory
	for key, connection := range h.serviceTokens {
		if connection.Token == nil || !connection.Token.Valid() {
			delete(h.serviceTokens, key)
		}
	}
	
	// Save the cleaned up tokens
	return h.SaveServiceTokens()
}