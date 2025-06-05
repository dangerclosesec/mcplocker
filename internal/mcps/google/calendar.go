package google

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dangerclosesec/mcplocker/internal/security"
	"golang.org/x/oauth2"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
)

// getUserEmail gets the user's email from their OAuth token
func getUserEmail(token *oauth2.Token) (string, error) {
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(token))
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo.Email, nil
}

// ExecuteCalendarTool executes Google Calendar API calls
func ExecuteCalendarTool(toolName string, parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	fmt.Printf("DEBUG: executeCalendarTool called with tool: %s, parameters: %+v\n", toolName, parameters)
	fmt.Printf("DEBUG: OAuth token valid: %t, expires: %v\n", token.Valid(), token.Expiry)

	switch toolName {
	case "calendar_create_event":
		return CreateCalendarEvent(parameters, token)
	case "calendar_update_event":
		return UpdateCalendarEvent(parameters, token)
	case "calendar_get_events":
		return GetCalendarEvents(parameters, token)
	default:
		return nil, fmt.Errorf("unsupported calendar tool: %s", toolName)
	}
}

// CreateCalendarEvent creates a new calendar event using Google Calendar API
func CreateCalendarEvent(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()

	// Validate input parameters
	if err := security.ValidateCalendarInput(parameters); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Sanitize input parameters
	security.SanitizeCalendarInput(parameters)

	// Create OAuth2 client with the user's token
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	// Create Calendar service
	service, err := calendar.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar service: %w", err)
	}

	// Extract parameters
	summary, ok := parameters["summary"].(string)
	if !ok {
		return nil, fmt.Errorf("summary parameter is required and must be a string")
	}

	startTime, ok := parameters["start_time"].(string)
	if !ok {
		return nil, fmt.Errorf("start_time parameter is required and must be a string")
	}

	endTime, ok := parameters["end_time"].(string)
	if !ok {
		return nil, fmt.Errorf("end_time parameter is required and must be a string")
	}

	// Parse times
	startDateTime, err := time.Parse(time.RFC3339, startTime)
	if err != nil {
		return nil, fmt.Errorf("invalid start_time format, expected RFC3339: %w", err)
	}

	endDateTime, err := time.Parse(time.RFC3339, endTime)
	if err != nil {
		return nil, fmt.Errorf("invalid end_time format, expected RFC3339: %w", err)
	}

	// Create the event
	event := &calendar.Event{
		Summary: summary,
		Start: &calendar.EventDateTime{
			DateTime: startDateTime.Format(time.RFC3339),
			TimeZone: "UTC",
		},
		End: &calendar.EventDateTime{
			DateTime: endDateTime.Format(time.RFC3339),
			TimeZone: "UTC",
		},
	}

	// Add optional fields
	if description, ok := parameters["description"].(string); ok && description != "" {
		event.Description = description
	}

	if location, ok := parameters["location"].(string); ok && location != "" {
		event.Location = location
	}

	// Get user's email to automatically add them as an attendee
	userEmail, err := getUserEmail(token)
	if err != nil {
		fmt.Printf("WARNING: Could not get user email, user won't be added as attendee: %v\n", err)
		userEmail = ""
	}

	// Collect all attendees (user + provided attendees)
	var attendees []*calendar.EventAttendee

	// Always add the user as an attendee if we have their email
	if userEmail != "" {
		attendees = append(attendees, &calendar.EventAttendee{
			Email:          userEmail,
			ResponseStatus: "accepted", // User automatically accepts their own events
		})
	}

	// Add additional attendees if provided
	if attendeesStr, ok := parameters["attendees"].(string); ok && attendeesStr != "" {
		attendeeEmails := strings.Split(attendeesStr, ",")
		for _, email := range attendeeEmails {
			email = strings.TrimSpace(email)
			if email != "" && email != userEmail { // Don't duplicate the user
				attendees = append(attendees, &calendar.EventAttendee{
					Email: email,
				})
			}
		}
	}

	if len(attendees) > 0 {
		event.Attendees = attendees
	}

	// Insert the event (default to primary calendar)
	calendarID := "primary"
	if calID, ok := parameters["calendar_id"].(string); ok && calID != "" {
		calendarID = calID
	}

	createdEvent, err := service.Events.Insert(calendarID, event).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar event: %w", err)
	}

	// Return success response
	result := map[string]interface{}{
		"success":     true,
		"message":     "Calendar event created successfully",
		"event_id":    createdEvent.Id,
		"event_link":  createdEvent.HtmlLink,
		"summary":     createdEvent.Summary,
		"start_time":  createdEvent.Start.DateTime,
		"end_time":    createdEvent.End.DateTime,
		"created":     createdEvent.Created,
		"calendar_id": calendarID,
	}

	fmt.Printf("DEBUG: Successfully created calendar event: %s (ID: %s)\n", createdEvent.Summary, createdEvent.Id)
	return result, nil
}

// UpdateCalendarEvent updates an existing calendar event using Google Calendar API
func UpdateCalendarEvent(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()

	// Validate input parameters
	if err := security.ValidateCalendarInput(parameters); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}

	// Sanitize input parameters
	security.SanitizeCalendarInput(parameters)

	// Create OAuth2 client with the user's token
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	// Create Calendar service
	service, err := calendar.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar service: %w", err)
	}

	// Extract required parameters
	eventID, ok := parameters["event_id"].(string)
	if !ok || eventID == "" {
		return nil, fmt.Errorf("event_id parameter is required and must be a string")
	}

	// Get calendar ID (default to primary)
	calendarID := "primary"
	if calID, ok := parameters["calendar_id"].(string); ok && calID != "" {
		calendarID = calID
	}

	// Get the existing event first
	existingEvent, err := service.Events.Get(calendarID, eventID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get existing event: %w", err)
	}

	// Update fields that are provided in parameters
	if summary, ok := parameters["summary"].(string); ok && summary != "" {
		existingEvent.Summary = summary
	}

	if description, ok := parameters["description"].(string); ok {
		existingEvent.Description = description
	}

	if location, ok := parameters["location"].(string); ok {
		existingEvent.Location = location
	}

	// Update times if provided
	if startTime, ok := parameters["start_time"].(string); ok && startTime != "" {
		startDateTime, err := time.Parse(time.RFC3339, startTime)
		if err != nil {
			return nil, fmt.Errorf("invalid start_time format, expected RFC3339: %w", err)
		}
		existingEvent.Start = &calendar.EventDateTime{
			DateTime: startDateTime.Format(time.RFC3339),
			TimeZone: "UTC",
		}
	}

	if endTime, ok := parameters["end_time"].(string); ok && endTime != "" {
		endDateTime, err := time.Parse(time.RFC3339, endTime)
		if err != nil {
			return nil, fmt.Errorf("invalid end_time format, expected RFC3339: %w", err)
		}
		existingEvent.End = &calendar.EventDateTime{
			DateTime: endDateTime.Format(time.RFC3339),
			TimeZone: "UTC",
		}
	}

	// Handle attendees updates
	if attendeesStr, ok := parameters["attendees"].(string); ok {
		// Get user's email to ensure they remain as an attendee
		userEmail, err := getUserEmail(token)
		if err != nil {
			fmt.Printf("WARNING: Could not get user email for attendee update: %v\n", err)
			userEmail = ""
		}

		// Collect all attendees (user + provided attendees)
		var attendees []*calendar.EventAttendee

		// Always keep the user as an attendee if we have their email
		if userEmail != "" {
			attendees = append(attendees, &calendar.EventAttendee{
				Email:          userEmail,
				ResponseStatus: "accepted",
			})
		}

		// Add provided attendees (if not empty string, which would clear attendees except user)
		if attendeesStr != "" {
			attendeeEmails := strings.Split(attendeesStr, ",")
			for _, email := range attendeeEmails {
				email = strings.TrimSpace(email)
				if email != "" && email != userEmail { // Don't duplicate the user
					attendees = append(attendees, &calendar.EventAttendee{
						Email: email,
					})
				}
			}
		}

		existingEvent.Attendees = attendees
	}

	// Update the event
	updatedEvent, err := service.Events.Update(calendarID, eventID, existingEvent).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to update calendar event: %w", err)
	}

	// Return success response
	result := map[string]interface{}{
		"success":     true,
		"message":     "Calendar event updated successfully",
		"event_id":    updatedEvent.Id,
		"event_link":  updatedEvent.HtmlLink,
		"summary":     updatedEvent.Summary,
		"start_time":  updatedEvent.Start.DateTime,
		"end_time":    updatedEvent.End.DateTime,
		"updated":     updatedEvent.Updated,
		"calendar_id": calendarID,
	}

	fmt.Printf("DEBUG: Successfully updated calendar event: %s (ID: %s)\n", updatedEvent.Summary, updatedEvent.Id)
	return result, nil
}

// GetCalendarEvents retrieves calendar events using Google Calendar API
func GetCalendarEvents(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()

	// Create OAuth2 client with the user's token
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))

	// Create Calendar service
	service, err := calendar.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create calendar service: %w", err)
	}

	// Set up query parameters
	calendarID := "primary"
	if calID, ok := parameters["calendar_id"].(string); ok && calID != "" {
		calendarID = calID
	}

	call := service.Events.List(calendarID)

	// Add optional time bounds
	if timeMin, ok := parameters["time_min"].(string); ok && timeMin != "" {
		call = call.TimeMin(timeMin)
	}

	if timeMax, ok := parameters["time_max"].(string); ok && timeMax != "" {
		call = call.TimeMax(timeMax)
	}

	// Set max results
	maxResults := int64(10)
	if maxRes, ok := parameters["max_results"].(float64); ok && maxRes > 0 {
		maxResults = int64(maxRes)
	}
	call = call.MaxResults(maxResults)

	// Execute the query
	events, err := call.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve calendar events: %w", err)
	}

	// Format the response
	var eventList []map[string]interface{}
	for _, event := range events.Items {
		eventInfo := map[string]interface{}{
			"id":          event.Id,
			"summary":     event.Summary,
			"description": event.Description,
			"location":    event.Location,
			"start_time":  event.Start.DateTime,
			"end_time":    event.End.DateTime,
			"html_link":   event.HtmlLink,
			"created":     event.Created,
			"updated":     event.Updated,
		}

		// Add attendees if present
		if len(event.Attendees) > 0 {
			var attendees []string
			for _, attendee := range event.Attendees {
				attendees = append(attendees, attendee.Email)
			}
			eventInfo["attendees"] = attendees
		}

		eventList = append(eventList, eventInfo)
	}

	result := map[string]interface{}{
		"success":     true,
		"message":     "Calendar events retrieved successfully",
		"events":      eventList,
		"total_count": len(eventList),
		"calendar_id": calendarID,
	}

	fmt.Printf("DEBUG: Retrieved %d calendar events\n", len(eventList))
	return result, nil
}
