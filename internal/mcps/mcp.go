// Example usage
// func main() {
//     RegisterMCP("example_mcp", "1.0.0", "An example MCP server", map[string]interface{}{"capability1": true})
//     mcp, exists := GetMCP("example_mcp")
//     if exists {
//         fmt.Println("MCP Name:", mcp.Name)
//         fmt.Println("MCP Version:", mcp.Version)
//         fmt.Println("MCP Description:", mcp.Description)
//         fmt.Println("MCP Capabilities:", mcp.Capabilities)
//     } else {
//         fmt.Println("MCP not found")
//     }
//
//     fmt.Println("All MCPs:", ListMCPs())
//     UnregisterMCP("example_mcp")
//     fmt.Println("All MCPs after unregistering:", ListMCPs())
// }

package mcps

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var mcps = &map[string]MCP{}

// MCP represents a minimal interface for MCP servers
type MCP struct {
	Tool    mcp.Tool
	Handler server.ToolHandlerFunc
}

func (m *MCP) GetTool() mcp.Tool {
	return m.Tool
}

func (m *MCP) GetHandler() server.ToolHandlerFunc {
	return m.Handler
}

// MCPServer is an interface that defines the methods required for an MCP server
type MCPServer interface {
	String() string
	GetTool() mcp.Tool
}

// RegisterMCP registers a new MCP server with the given name and version
func RegisterMCP(tool mcp.Tool, handler server.ToolHandlerFunc) {
	name := tool.Name
	if _, exists := (*mcps)[name]; exists {
		panic("MCP server already registered: " + name)
	}
	(*mcps)[name] = MCP{
		Tool:    tool,
		Handler: handler,
	}
}

// GetMCP retrieves an MCP server by name
func GetMCP(name string) (*MCP, bool) {
	mcp, exists := (*mcps)[name]
	if !exists {
		return nil, false
	}
	return &mcp, true
}

// ListMCPs returns a list of all registered MCP servers
func ListMCPs() []MCP {
	mcpList := make([]MCP, 0, len(*mcps))
	for _, mcp := range *mcps {
		mcpList = append(mcpList, mcp)
	}
	return mcpList
}

// UnregisterMCP removes an MCP server by name
func UnregisterMCP(name string) {
	delete(*mcps, name)
}
