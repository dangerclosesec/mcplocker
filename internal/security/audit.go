package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Authentication events
	AuditLoginSuccess AuditEventType = "auth.login.success"
	AuditLoginFailure AuditEventType = "auth.login.failure"
	AuditLogout       AuditEventType = "auth.logout"
	AuditTokenCreated AuditEventType = "auth.token.created"
	AuditTokenRevoked AuditEventType = "auth.token.revoked"

	// Service connection events
	AuditServiceConnected    AuditEventType = "service.connected"
	AuditServiceDisconnected AuditEventType = "service.disconnected"
	AuditServiceAuthFailed   AuditEventType = "service.auth.failed"

	// Tool execution events
	AuditToolExecuted    AuditEventType = "tool.executed"
	AuditToolFailed      AuditEventType = "tool.failed"
	AuditToolRateLimited AuditEventType = "tool.rate_limited"

	// Security events
	AuditSecurityViolation  AuditEventType = "security.violation"
	AuditValidationFailed   AuditEventType = "security.validation_failed"
	AuditSuspiciousActivity AuditEventType = "security.suspicious_activity"
)

// AuditEvent represents a security audit log entry
type AuditEvent struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	EventType AuditEventType         `json:"event_type"`
	UserID    string                 `json:"user_id,omitempty"`
	UserEmail string                 `json:"user_email,omitempty"`
	Service   string                 `json:"service,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Resource  string                 `json:"resource,omitempty"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Success   bool                   `json:"success"`
	ErrorCode string                 `json:"error_code,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	SessionID string                 `json:"session_id,omitempty"`
}

// AuditLogger handles security audit logging
type AuditLogger struct {
	logFile string
	mutex   sync.Mutex
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger() (*AuditLogger, error) {
	// Create logs directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	logDir := filepath.Join(homeDir, ".config", "mcplocker", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	logFile := filepath.Join(logDir, "security_audit.log")
	return &AuditLogger{
		logFile: logFile,
	}, nil
}

// LogEvent logs a security audit event
func (a *AuditLogger) LogEvent(event AuditEvent) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Set timestamp and ID if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.ID == "" {
		event.ID = generateEventID()
	}

	// Hash sensitive data
	if event.UserID != "" {
		event.UserID = hashSensitiveData(event.UserID)
	}
	if event.SessionID != "" {
		event.SessionID = hashSensitiveData(event.SessionID)
	}

	// Serialize event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Append to log file
	file, err := os.OpenFile(a.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString(string(eventJSON) + "\n"); err != nil {
		return fmt.Errorf("failed to write audit log: %w", err)
	}

	return nil
}

// LogAuthSuccess logs successful authentication
func (a *AuditLogger) LogAuthSuccess(userID, userEmail, ipAddress, userAgent string) {
	event := AuditEvent{
		EventType: AuditLoginSuccess,
		UserID:    userID,
		UserEmail: userEmail,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   true,
		Message:   "User authentication successful",
	}
	a.LogEvent(event)
}

// LogAuthFailure logs failed authentication
func (a *AuditLogger) LogAuthFailure(userEmail, ipAddress, userAgent, reason string) {
	event := AuditEvent{
		EventType: AuditLoginFailure,
		UserEmail: userEmail,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Success:   false,
		Message:   "User authentication failed",
		Details: map[string]interface{}{
			"failure_reason": reason,
		},
	}
	a.LogEvent(event)
}

// LogServiceConnection logs service connection events
func (a *AuditLogger) LogServiceConnection(userID, service, ipAddress string, success bool, errorMsg string) {
	eventType := AuditServiceConnected
	if !success {
		eventType = AuditServiceAuthFailed
	}

	event := AuditEvent{
		EventType: eventType,
		UserID:    userID,
		Service:   service,
		IPAddress: ipAddress,
		Success:   success,
		Message:   fmt.Sprintf("Service %s connection", service),
	}

	if errorMsg != "" {
		event.Details = map[string]interface{}{
			"error": errorMsg,
		}
	}

	a.LogEvent(event)
}

// LogToolExecution logs tool execution events
func (a *AuditLogger) LogToolExecution(userID, toolName, service, ipAddress string, success bool, errorMsg string, duration time.Duration) {
	eventType := AuditToolExecuted
	if !success {
		eventType = AuditToolFailed
	}

	event := AuditEvent{
		EventType: eventType,
		UserID:    userID,
		Service:   service,
		Action:    toolName,
		IPAddress: ipAddress,
		Success:   success,
		Message:   fmt.Sprintf("Tool %s execution", toolName),
		Details: map[string]interface{}{
			"execution_duration_ms": duration.Milliseconds(),
		},
	}

	if errorMsg != "" {
		event.Details["error"] = errorMsg
	}

	a.LogEvent(event)
}

// LogSecurityViolation logs security violations
func (a *AuditLogger) LogSecurityViolation(userID, ipAddress, violation, details string) {
	event := AuditEvent{
		EventType: AuditSecurityViolation,
		UserID:    userID,
		IPAddress: ipAddress,
		Success:   false,
		Message:   "Security violation detected",
		Details: map[string]interface{}{
			"violation_type": violation,
			"details":        details,
		},
	}
	a.LogEvent(event)
}

// LogValidationFailure logs input validation failures
func (a *AuditLogger) LogValidationFailure(userID, toolName, field, reason, ipAddress string) {
	event := AuditEvent{
		EventType: AuditValidationFailed,
		UserID:    userID,
		Action:    toolName,
		IPAddress: ipAddress,
		Success:   false,
		Message:   "Input validation failed",
		Details: map[string]interface{}{
			"field":  field,
			"reason": reason,
		},
	}
	a.LogEvent(event)
}

// LogRateLimitExceeded logs rate limit violations
func (a *AuditLogger) LogRateLimitExceeded(userID, service, ipAddress string) {
	event := AuditEvent{
		EventType: AuditToolRateLimited,
		UserID:    userID,
		Service:   service,
		IPAddress: ipAddress,
		Success:   false,
		Message:   "Rate limit exceeded",
	}
	a.LogEvent(event)
}

// Helper functions

// generateEventID generates a unique event ID
func generateEventID() string {
	now := time.Now()
	data := fmt.Sprintf("%d_%d", now.UnixNano(), os.Getpid())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

// hashSensitiveData hashes sensitive data for logging
func hashSensitiveData(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16] // Return first 16 chars for readability
}

// Global audit logger instance
var GlobalAuditLogger *AuditLogger

// InitializeAuditLogger initializes the global audit logger
func InitializeAuditLogger() error {
	logger, err := NewAuditLogger()
	if err != nil {
		return err
	}
	GlobalAuditLogger = logger
	return nil
}
