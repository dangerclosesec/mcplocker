package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the mcplocker configuration
type Config struct {
	AuthServerURL string       `json:"auth_server_url"`
	Token         string       `json:"token"`
	Tools         []ToolConfig `json:"tools"`
}

// ToolConfig represents a configured MCP tool
type ToolConfig struct {
	Name          string            `json:"name"`
	Provider      string            `json:"provider"` // e.g., "google", "slack"
	Service       string            `json:"service"`  // e.g., "calendar", "gmail", "channels"
	Enabled       bool              `json:"enabled"`
	Authenticated bool              `json:"authenticated"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		AuthServerURL: "http://localhost:38741",
		Token:         "",
		Tools:         []ToolConfig{},
	}
}

// GetConfigPath returns the path to the configuration file
func GetConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".config", "mcplocker")
	configFile := filepath.Join(configDir, "mcp.json")

	return configFile, nil
}

// EnsureConfigDir creates the config directory if it doesn't exist
func EnsureConfigDir() error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	configDir := filepath.Dir(configPath)
	return os.MkdirAll(configDir, 0755)
}

// Load loads the configuration from the config file
func Load() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		return nil, err
	}

	// If config file doesn't exist, return default config
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// Save saves the configuration to the config file
func (c *Config) Save() error {
	if err := EnsureConfigDir(); err != nil {
		return err
	}

	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// AddTool adds or updates a tool configuration
func (c *Config) AddTool(tool ToolConfig) {
	for i, existingTool := range c.Tools {
		if existingTool.Name == tool.Name {
			c.Tools[i] = tool
			return
		}
	}
	c.Tools = append(c.Tools, tool)
}

// GetTool retrieves a tool configuration by name
func (c *Config) GetTool(name string) (*ToolConfig, bool) {
	for _, tool := range c.Tools {
		if tool.Name == name {
			return &tool, true
		}
	}
	return nil, false
}

// RemoveTool removes a tool configuration by name
func (c *Config) RemoveTool(name string) bool {
	for i, tool := range c.Tools {
		if tool.Name == name {
			c.Tools = append(c.Tools[:i], c.Tools[i+1:]...)
			return true
		}
	}
	return false
}

// GetEnabledTools returns all enabled tool configurations
func (c *Config) GetEnabledTools() []ToolConfig {
	var enabled []ToolConfig
	for _, tool := range c.Tools {
		if tool.Enabled {
			enabled = append(enabled, tool)
		}
	}
	return enabled
}

// GetAuthenticatedTools returns all authenticated tool configurations
func (c *Config) GetAuthenticatedTools() []ToolConfig {
	var authenticated []ToolConfig
	for _, tool := range c.Tools {
		if tool.Authenticated {
			authenticated = append(authenticated, tool)
		}
	}
	return authenticated
}

// HasValidToken checks if the configuration has a valid token
func (c *Config) HasValidToken() bool {
	return c.Token != ""
}

// SetToken sets the authentication token
func (c *Config) SetToken(token string) {
	c.Token = token
}

// SetAuthServerURL sets the authentication server URL
func (c *Config) SetAuthServerURL(url string) {
	c.AuthServerURL = url
}
