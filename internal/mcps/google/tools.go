package google

import (
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

// ExecuteGoogleTool executes Google API calls based on the tool name
func ExecuteGoogleTool(toolName string, parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	service := getServiceFromToolName(toolName)
	
	switch service {
	case "gmail":
		return ExecuteGmailTool(toolName, parameters, token)
	case "calendar":
		return ExecuteCalendarTool(toolName, parameters, token)
	case "drive":
		return ExecuteDriveTool(toolName, parameters, token)
	default:
		return nil, fmt.Errorf("unsupported Google service: %s", service)
	}
}

// getServiceFromToolName extracts the service name from a Google tool name
func getServiceFromToolName(toolName string) string {
	switch {
	case strings.Contains(toolName, "gmail"):
		return "gmail"
	case strings.Contains(toolName, "calendar"):
		return "calendar"
	case strings.Contains(toolName, "drive"):
		return "drive"
	default:
		return ""
	}
}