package calendar

import (
	"context"
	"fmt"

	"github.com/dangerclosesec/mcplocker/internal/mcps"
	"github.com/mark3labs/mcp-go/mcp"
)

func init() {
	// Register the Google Calendar MCP with the MCP server
	mcps.RegisterMCP(
		mcp.NewTool("google_calendar_get_calendar_events",
			mcp.WithDescription("Get a calendar event from Google Calendar"),
			mcp.WithString("event_name",
				mcp.Description("Name of the event to find"),
			),
			mcp.WithString("event_date",
				mcp.Description("Date of the event in YYYY-MM-DD format"),
			),
			mcp.WithString("guest_email",
				mcp.Description("Email of the guest who was invited"),
			),
		),
		GetCalendarEventsHandler,
	)
}

func GetCalendarEventsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := request.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Hello, %s!", name)), nil
}
