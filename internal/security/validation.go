package security

import (
	"fmt"
	"html"
	"net/mail"
	"regexp"
	"strings"
	"time"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Input limits and constraints
const (
	MaxSummaryLength     = 1000
	MaxDescriptionLength = 8000
	MaxLocationLength    = 500
	MaxAttendeesCount    = 100
	MaxEventDurationDays = 30
)

// HTML tag detection regex
var htmlTagRegex = regexp.MustCompile(`<[^>]*>`)

// ValidateCalendarInput validates calendar event input parameters
func ValidateCalendarInput(parameters map[string]interface{}) error {
	// Validate summary
	if summary, ok := parameters["summary"].(string); ok && summary != "" {
		if err := validateSummary(summary); err != nil {
			return err
		}
	}

	// Validate description
	if description, ok := parameters["description"].(string); ok && description != "" {
		if err := validateDescription(description); err != nil {
			return err
		}
	}

	// Validate location
	if location, ok := parameters["location"].(string); ok && location != "" {
		if err := validateLocation(location); err != nil {
			return err
		}
	}

	// Validate attendees
	if attendees, ok := parameters["attendees"].(string); ok && attendees != "" {
		if err := validateAttendees(attendees); err != nil {
			return err
		}
	}

	// Validate event times
	if err := validateEventTimes(parameters); err != nil {
		return err
	}

	// Validate event ID if present (for updates)
	if eventID, ok := parameters["event_id"].(string); ok && eventID != "" {
		if err := validateEventID(eventID); err != nil {
			return err
		}
	}

	return nil
}

// validateSummary validates event summary/title
func validateSummary(summary string) error {
	if len(summary) > MaxSummaryLength {
		return ValidationError{
			Field:   "summary",
			Message: fmt.Sprintf("exceeds maximum length of %d characters", MaxSummaryLength),
		}
	}

	if containsHTMLTags(summary) {
		return ValidationError{
			Field:   "summary",
			Message: "HTML tags are not allowed",
		}
	}

	if containsSuspiciousContent(summary) {
		return ValidationError{
			Field:   "summary",
			Message: "contains potentially malicious content",
		}
	}

	return nil
}

// validateDescription validates event description
func validateDescription(description string) error {
	if len(description) > MaxDescriptionLength {
		return ValidationError{
			Field:   "description",
			Message: fmt.Sprintf("exceeds maximum length of %d characters", MaxDescriptionLength),
		}
	}

	if containsSuspiciousContent(description) {
		return ValidationError{
			Field:   "description",
			Message: "contains potentially malicious content",
		}
	}

	return nil
}

// validateLocation validates event location
func validateLocation(location string) error {
	if len(location) > MaxLocationLength {
		return ValidationError{
			Field:   "location",
			Message: fmt.Sprintf("exceeds maximum length of %d characters", MaxLocationLength),
		}
	}

	if containsHTMLTags(location) {
		return ValidationError{
			Field:   "location",
			Message: "HTML tags are not allowed",
		}
	}

	return nil
}

// validateAttendees validates attendee email list
func validateAttendees(attendees string) error {
	emails := strings.Split(attendees, ",")

	if len(emails) > MaxAttendeesCount {
		return ValidationError{
			Field:   "attendees",
			Message: fmt.Sprintf("too many attendees (maximum %d allowed)", MaxAttendeesCount),
		}
	}

	for i, email := range emails {
		email = strings.TrimSpace(email)
		if email == "" {
			continue
		}

		if !isValidEmail(email) {
			return ValidationError{
				Field:   "attendees",
				Message: fmt.Sprintf("invalid email address at position %d: %s", i+1, email),
			}
		}
	}

	return nil
}

// validateEventTimes validates start and end times
func validateEventTimes(parameters map[string]interface{}) error {
	startTimeStr, hasStart := parameters["start_time"].(string)
	endTimeStr, hasEnd := parameters["end_time"].(string)

	if !hasStart && !hasEnd {
		return nil // No time validation needed if neither is provided
	}

	if hasStart && hasEnd {
		startTime, err := time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			return ValidationError{
				Field:   "start_time",
				Message: "invalid RFC3339 format",
			}
		}

		endTime, err := time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			return ValidationError{
				Field:   "end_time",
				Message: "invalid RFC3339 format",
			}
		}

		// Check if end time is after start time
		if !endTime.After(startTime) {
			return ValidationError{
				Field:   "end_time",
				Message: "must be after start_time",
			}
		}

		// Check event duration
		duration := endTime.Sub(startTime)
		maxDuration := time.Duration(MaxEventDurationDays) * 24 * time.Hour
		if duration > maxDuration {
			return ValidationError{
				Field:   "duration",
				Message: fmt.Sprintf("event duration exceeds maximum of %d days", MaxEventDurationDays),
			}
		}

		// Prevent events too far in the future (calendar bombing prevention)
		if startTime.After(time.Now().Add(365 * 24 * time.Hour)) {
			return ValidationError{
				Field:   "start_time",
				Message: "event cannot be scheduled more than 1 year in the future",
			}
		}
	}

	return nil
}

// validateEventID validates Google Calendar event ID format
func validateEventID(eventID string) error {
	// Google Calendar event IDs are typically alphanumeric with underscores
	// Length is usually between 10-100 characters
	if len(eventID) < 5 || len(eventID) > 100 {
		return ValidationError{
			Field:   "event_id",
			Message: "invalid event ID length",
		}
	}

	// Basic alphanumeric + underscore validation
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, eventID)
	if !matched {
		return ValidationError{
			Field:   "event_id",
			Message: "contains invalid characters",
		}
	}

	return nil
}

// SanitizeInput sanitizes user input by escaping HTML and trimming whitespace
func SanitizeInput(input string) string {
	// Trim whitespace
	sanitized := strings.TrimSpace(input)

	// Escape HTML to prevent XSS
	sanitized = html.EscapeString(sanitized)

	return sanitized
}

// SanitizeCalendarInput sanitizes all string fields in calendar parameters
func SanitizeCalendarInput(parameters map[string]interface{}) {
	stringFields := []string{"summary", "description", "location", "attendees", "calendar_id"}

	for _, field := range stringFields {
		if value, ok := parameters[field].(string); ok {
			parameters[field] = SanitizeInput(value)
		}
	}
}

// Helper functions

// isValidEmail validates email address format
func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// containsHTMLTags checks if string contains HTML tags
func containsHTMLTags(input string) bool {
	return htmlTagRegex.MatchString(input)
}

// containsSuspiciousContent checks for potentially malicious content
func containsSuspiciousContent(input string) bool {
	suspicious := []string{
		"<script",
		"javascript:",
		"data:",
		"vbscript:",
		"onload=",
		"onerror=",
		"onclick=",
		"onmouseover=",
		"eval(",
		"expression(",
	}

	lowerInput := strings.ToLower(input)
	for _, pattern := range suspicious {
		if strings.Contains(lowerInput, pattern) {
			return true
		}
	}

	return false
}
