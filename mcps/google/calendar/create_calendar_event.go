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
		mcp.NewTool("google_calendar_create_calendar_event",
			mcp.WithDescription("Create a calendar event in Google Calendar"),
			mcp.WithString("event_name",
				mcp.Required(),
				mcp.Description("Name of the event to create"),
			),
			mcp.WithString("event_date",
				mcp.Required(),
				mcp.Description("Date of the event in YYYY-MM-DD format"),
			),
		),
		CreateCalendarEventHandler,
	)
}

func CreateCalendarEventHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := request.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Hello, %s!", name)), nil
}
