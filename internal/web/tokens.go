package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// APIToken represents a long-lived API token for CLI access
type APIToken struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Token       string     `json:"token"` // Hashed version for storage
	UserID      string     `json:"user_id"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Permissions []string   `json:"permissions"`
	Status      string     `json:"status"` // "active", "revoked", "expired"
}

// TokenCreateRequest represents a request to create a new token
type TokenCreateRequest struct {
	Name        string   `json:"name"`
	ExpiresIn   *int     `json:"expires_in"` // Optional expiration in seconds
	Permissions []string `json:"permissions,omitempty"`
}

// TokenCreateResponse represents the response when creating a token
type TokenCreateResponse struct {
	*APIToken
	PlainToken string `json:"token"` // Plain text token (only shown once)
}

// TokenManager handles API token storage and management
type TokenManager struct {
	tokens   map[string]*APIToken // keyed by token ID
	userKeys map[string][]string  // userID -> list of token IDs
	mutex    sync.RWMutex
	dataFile string
}

// NewTokenManager creates a new token manager
func NewTokenManager() (*TokenManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	tokenDir := filepath.Join(homeDir, ".config", "mcplocker")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create token directory: %w", err)
	}

	dataFile := filepath.Join(tokenDir, "api_tokens.json")

	tm := &TokenManager{
		tokens:   make(map[string]*APIToken),
		userKeys: make(map[string][]string),
		dataFile: dataFile,
	}

	// Load existing tokens
	if err := tm.loadTokens(); err != nil {
		return nil, fmt.Errorf("failed to load tokens: %w", err)
	}

	return tm, nil
}

// CreateToken creates a new API token
func (tm *TokenManager) CreateToken(userID string, req TokenCreateRequest) (*TokenCreateResponse, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	// Generate token ID and plain token
	tokenID := generateTokenID()
	plainToken := generatePlainToken()
	hashedToken := hashToken(plainToken)

	// Set expiration if provided
	var expiresAt *time.Time
	if req.ExpiresIn != nil && *req.ExpiresIn > 0 {
		exp := time.Now().Add(time.Duration(*req.ExpiresIn) * time.Second)
		expiresAt = &exp
	}

	// Create token
	token := &APIToken{
		ID:          tokenID,
		Name:        req.Name,
		Token:       hashedToken,
		UserID:      userID,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Permissions: req.Permissions,
		Status:      "active",
	}

	// Store token
	tm.tokens[tokenID] = token

	// Update user index
	if tm.userKeys[userID] == nil {
		tm.userKeys[userID] = []string{}
	}
	tm.userKeys[userID] = append(tm.userKeys[userID], tokenID)

	// Save to disk
	if err := tm.saveTokens(); err != nil {
		return nil, fmt.Errorf("failed to save tokens: %w", err)
	}

	return &TokenCreateResponse{
		APIToken:   token,
		PlainToken: plainToken,
	}, nil
}

// GetUserTokens returns all tokens for a specific user
func (tm *TokenManager) GetUserTokens(userID string) []*APIToken {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	var tokens []*APIToken
	if tokenIDs, exists := tm.userKeys[userID]; exists {
		for _, tokenID := range tokenIDs {
			if token, exists := tm.tokens[tokenID]; exists {
				// Create a copy to avoid exposing the hashed token
				tokenCopy := *token
				tokenCopy.Token = maskToken(token.Token)
				tokens = append(tokens, &tokenCopy)
			}
		}
	}

	return tokens
}

// ValidateToken validates a plain token and returns the associated token info
func (tm *TokenManager) ValidateToken(plainToken string) (*APIToken, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	hashedToken := hashToken(plainToken)

	// Find token by hashed value
	for _, token := range tm.tokens {
		if token.Token == hashedToken {
			// Check if token is still valid
			if token.Status != "active" {
				return nil, fmt.Errorf("token is not active")
			}

			if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
				// Mark as expired and save
				token.Status = "expired"
				tm.saveTokens()
				return nil, fmt.Errorf("token has expired")
			}

			// Update last used time
			now := time.Now()
			token.LastUsed = &now
			tm.saveTokens()

			return token, nil
		}
	}

	return nil, fmt.Errorf("invalid token")
}

// RevokeToken revokes a token
func (tm *TokenManager) RevokeToken(userID, tokenID string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token not found")
	}

	if token.UserID != userID {
		return fmt.Errorf("token does not belong to user")
	}

	token.Status = "revoked"

	return tm.saveTokens()
}

// DeleteToken permanently deletes a token
func (tm *TokenManager) DeleteToken(userID, tokenID string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	token, exists := tm.tokens[tokenID]
	if !exists {
		return fmt.Errorf("token not found")
	}

	if token.UserID != userID {
		return fmt.Errorf("token does not belong to user")
	}

	// Remove from tokens map
	delete(tm.tokens, tokenID)

	// Remove from user index
	if tokenIDs, exists := tm.userKeys[userID]; exists {
		for i, id := range tokenIDs {
			if id == tokenID {
				tm.userKeys[userID] = append(tokenIDs[:i], tokenIDs[i+1:]...)
				break
			}
		}
	}

	return tm.saveTokens()
}

// CleanupExpiredTokens removes expired tokens
func (tm *TokenManager) CleanupExpiredTokens() error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	now := time.Now()
	var tokensToDelete []string

	for tokenID, token := range tm.tokens {
		if token.ExpiresAt != nil && token.ExpiresAt.Before(now) {
			token.Status = "expired"
			// Optionally delete very old expired tokens
			if token.ExpiresAt.Before(now.Add(-30 * 24 * time.Hour)) { // 30 days old
				tokensToDelete = append(tokensToDelete, tokenID)
			}
		}
	}

	// Delete old expired tokens
	for _, tokenID := range tokensToDelete {
		token := tm.tokens[tokenID]
		delete(tm.tokens, tokenID)

		// Remove from user index
		if tokenIDs, exists := tm.userKeys[token.UserID]; exists {
			for i, id := range tokenIDs {
				if id == tokenID {
					tm.userKeys[token.UserID] = append(tokenIDs[:i], tokenIDs[i+1:]...)
					break
				}
			}
		}
	}

	return tm.saveTokens()
}

// loadTokens loads tokens from disk
func (tm *TokenManager) loadTokens() error {
	if _, err := os.Stat(tm.dataFile); os.IsNotExist(err) {
		return nil // No file exists yet, that's OK
	}

	data, err := os.ReadFile(tm.dataFile)
	if err != nil {
		return fmt.Errorf("failed to read tokens file: %w", err)
	}

	var fileData struct {
		Tokens   map[string]*APIToken `json:"tokens"`
		UserKeys map[string][]string  `json:"user_keys"`
	}

	if err := json.Unmarshal(data, &fileData); err != nil {
		return fmt.Errorf("failed to unmarshal tokens: %w", err)
	}

	tm.tokens = fileData.Tokens
	tm.userKeys = fileData.UserKeys

	if tm.tokens == nil {
		tm.tokens = make(map[string]*APIToken)
	}
	if tm.userKeys == nil {
		tm.userKeys = make(map[string][]string)
	}

	return nil
}

// saveTokens saves tokens to disk
func (tm *TokenManager) saveTokens() error {
	fileData := struct {
		Tokens   map[string]*APIToken `json:"tokens"`
		UserKeys map[string][]string  `json:"user_keys"`
	}{
		Tokens:   tm.tokens,
		UserKeys: tm.userKeys,
	}

	data, err := json.MarshalIndent(fileData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	return os.WriteFile(tm.dataFile, data, 0600)
}

// Helper functions

// generateTokenID generates a unique token ID
func generateTokenID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generatePlainToken generates a plain text token
func generatePlainToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "mcp_" + base64.URLEncoding.EncodeToString(b)
}

// hashToken hashes a plain token for storage
func hashToken(plainToken string) string {
	h := sha256.Sum256([]byte(plainToken))
	return hex.EncodeToString(h[:])
}

// maskToken creates a masked version of a token for display
func maskToken(hashedToken string) string {
	if len(hashedToken) > 16 {
		return hashedToken[:8] + "..." + hashedToken[len(hashedToken)-8:]
	}
	return hashedToken[:8] + "..."
}
