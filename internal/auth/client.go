package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/dangerclosesec/mcplocker/internal/config"
)

// Client handles communication with the auth server
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new auth client
func NewClient(cfg *config.Config) *Client {
	return &Client{
		baseURL: cfg.AuthServerURL,
		token:   cfg.Token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ProxyRequest represents a request to proxy an MCP tool call
type ProxyRequest struct {
	ToolName   string                 `json:"tool_name"`
	Parameters map[string]interface{} `json:"parameters"`
}

// ProxyResponse represents the response from a proxied tool call
type ProxyResponse struct {
	Success bool        `json:"success"`
	Result  interface{} `json:"result,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// AuthRequest represents an authentication request
type AuthRequest struct {
	Provider string `json:"provider"` // e.g., "google", "slack"
	Service  string `json:"service"`  // e.g., "calendar", "gmail"
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	Success   bool   `json:"success"`
	AuthURL   string `json:"auth_url,omitempty"`
	Message   string `json:"message,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ToolStatusResponse represents the status of available tools
type ToolStatusResponse struct {
	Tools []config.ToolConfig `json:"tools"`
}

// makeRequest makes an authenticated HTTP request to the auth server
func (c *Client) makeRequest(ctx context.Context, method, endpoint string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	url := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

// ProxyToolCall forwards an MCP tool call to the auth server
func (c *Client) ProxyToolCall(ctx context.Context, toolName string, parameters map[string]interface{}) (*ProxyResponse, error) {
	req := ProxyRequest{
		ToolName:   toolName,
		Parameters: parameters,
	}

	resp, err := c.makeRequest(ctx, "POST", "/api/proxy/tool", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		// Read the response body for error details
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("proxy request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var proxyResp ProxyResponse
	if err := json.NewDecoder(resp.Body).Decode(&proxyResp); err != nil {
		// Read the actual response to see what we got
		resp.Body.Close()
		resp, _ = c.makeRequest(ctx, "POST", "/api/proxy/tool", req)
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to decode proxy response: %w (response body: %s)", err, string(body))
	}

	return &proxyResp, nil
}

// StartAuth initiates the OAuth flow for a provider/service
func (c *Client) StartAuth(ctx context.Context, provider, service string) (*AuthResponse, error) {
	req := AuthRequest{
		Provider: provider,
		Service:  service,
	}

	resp, err := c.makeRequest(ctx, "POST", "/api/auth/start", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return nil, fmt.Errorf("failed to decode auth response: %w", err)
	}

	return &authResp, nil
}

// GetToolStatus retrieves the status of all configured tools from the auth server
func (c *Client) GetToolStatus(ctx context.Context) (*ToolStatusResponse, error) {
	resp, err := c.makeRequest(ctx, "GET", "/api/tools/status", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var statusResp ToolStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode tool status response: %w", err)
	}

	return &statusResp, nil
}

// GetAvailableTools retrieves available tools based on user's authenticated services
func (c *Client) GetAvailableTools(ctx context.Context) (*ToolStatusResponse, error) {
	resp, err := c.makeRequest(ctx, "GET", "/api/tools/available", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get available tools: status %d", resp.StatusCode)
	}

	var toolsResp ToolStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&toolsResp); err != nil {
		return nil, fmt.Errorf("failed to decode available tools response: %w", err)
	}

	return &toolsResp, nil
}

// ValidateToken checks if the current token is valid
func (c *Client) ValidateToken(ctx context.Context) error {
	resp, err := c.makeRequest(ctx, "GET", "/api/auth/validate", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token validation failed with status: %d", resp.StatusCode)
	}

	return nil
}

// Ping checks if the auth server is reachable
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.makeRequest(ctx, "GET", "/health", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth server health check failed with status: %d", resp.StatusCode)
	}

	return nil
}