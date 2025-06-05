![MCPLocker Logo](.github/logo.png)
# MCP Locker

**MCPLocker** is an MCP-server credential manager written in Golang to help normalize and simplify the user credential process. It provides secure OAuth2 authentication for third-party services and acts as a proxy for MCP tool calls.

## Features

- 🔐 **Secure OAuth2 Authentication** - Manage credentials for Google, GitHub, and other services
- 🛡️ **Token-based Authorization** - CLI tools authenticate using secure API tokens
- 🌐 **Web Dashboard** - Browser-based interface for managing service connections
- 📅 **Google Calendar Integration** - Create and manage calendar events
- 📧 **Gmail Integration** - Send and read emails (planned)
- 💾 **Google Drive Integration** - Manage files and documents (planned)
- 🐙 **GitHub Integration** - Access repositories, manage issues, and inspect configurations
- 🔄 **MCP Proxy** - Forward tool calls through authenticated services

## Quick Start

### 1. Prerequisites

- Go 1.24+ installed
- Google Cloud Console project (for Google services)
- GitHub account (for GitHub services)

### 2. Build MCPLocker

```bash
git clone https://github.com/dangerclosesec/mcplocker.git
cd mcplocker
go build -o bin/authserver ./cmd/authserver
go build -o bin/mcplocker ./cmd/cli
```

### 3. Set up Google OAuth2 (Required for Google Services)

#### Create OAuth2 Credentials in Google Cloud Console

1. **Go to Google Cloud Console**
   - Visit [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select an existing one

2. **Enable APIs**
   - Navigate to "APIs & Services" > "Library"
   - Enable the following APIs:
     - Google Calendar API
     - Gmail API (if using email features)
     - Google Drive API (if using drive features)

3. **Create OAuth2 Credentials**
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application" as application type
   - Add authorized redirect URIs:
     ```
     http://localhost:38741/api/auth/callback/google
     ```
   - Download the JSON file

4. **Configure MCPLocker**
   - Create a `.secrets` file in the project root:
   ```json
   {
     "google": {
       "client_id": "your-client-id.googleusercontent.com",
       "client_secret": "your-client-secret",
       "auth_uri": "https://accounts.google.com/o/oauth2/auth",
       "token_uri": "https://oauth2.googleapis.com/token",
       "redirect_uri": "http://localhost:38741/api/auth/callback/google"
     }
   }
   ```

### 4. Set up GitHub OAuth2 (Required for GitHub Services)

#### Create OAuth App in GitHub

1. **Go to GitHub Settings**
   - Visit [GitHub Developer Settings](https://github.com/settings/developers)
   - Or navigate: Settings > Developer settings > OAuth Apps

2. **Create a New OAuth App**
   - Click "New OAuth App"
   - Fill in the application details:
     - **Application name**: `MCPLocker` (or your preferred name)
     - **Homepage URL**: `http://localhost:38741` (or your domain)
     - **Authorization callback URL**: `http://localhost:38741/api/auth/callback/github`
   - Click "Register application"

3. **Get Client Credentials**
   - After creating the app, you'll see your **Client ID**
   - Click "Generate a new client secret" to get your **Client Secret**
   - **Important**: Copy the client secret immediately as it won't be shown again

4. **Configure MCPLocker Environment Variables**
   ```bash
   # Add these to your environment (e.g., .bashrc, .zshrc, or .env file)
   export GITHUB_CLIENT_ID="your-github-client-id"
   export GITHUB_CLIENT_SECRET="your-github-client-secret"
   ```

   Or set them when running the auth server:
   ```bash
   GITHUB_CLIENT_ID="your-client-id" GITHUB_CLIENT_SECRET="your-client-secret" ./bin/authserver
   ```

#### GitHub OAuth Scopes

MCPLocker requests the following scopes based on the service:

- **Repository service** (`repo`, `read:user`):
  - Full access to private and public repositories
  - Read user profile data
  
- **Issues service** (`repo`, `read:user`):
  - Access to repository issues
  - Read user profile data

### 5. Start the Auth Server

```bash
./bin/authserver
```

The server will start on `http://localhost:38741`

### 6. Authenticate the CLI

```bash
# Set the server URL (if different from default)
./bin/mcplocker config set-server http://localhost:38741

# Authenticate with the server
./bin/mcplocker auth

# Check status
./bin/mcplocker status
```

### 7. Connect Services

1. **Open the web dashboard**: `http://localhost:38741`
2. **Sign in** with your Google account
3. **Navigate to Services** and connect:

#### Google Services
   - Google Calendar
   - Gmail (optional)
   - Google Drive (optional)

#### GitHub Services
   - GitHub Repositories - Access repos, view code, manage configurations
   - GitHub Issues - Create, view, and manage issues

### 8. Use as MCP Server

```bash
# Run as MCP server (for use with Claude Desktop or other MCP clients)
./bin/mcplocker
```

## Google Calendar Integration

### Available Tools

#### `calendar_create_event`
Creates a new calendar event.

**Parameters:**
- `summary` (required): Event title
- `start_time` (required): Start time in RFC3339 format (e.g., "2025-06-04T14:00:00Z")
- `end_time` (required): End time in RFC3339 format (e.g., "2025-06-04T15:00:00Z")
- `description` (optional): Event description
- `location` (optional): Event location
- `attendees` (optional): Comma-separated list of email addresses
- `calendar_id` (optional): Calendar ID (defaults to "primary")

**Example Usage:**
```json
{
  "tool": "calendar_create_event",
  "parameters": {
    "summary": "Team Meeting",
    "start_time": "2025-06-04T14:00:00Z",
    "end_time": "2025-06-04T15:00:00Z",
    "description": "Weekly team sync",
    "location": "Conference Room A",
    "attendees": "john@example.com,jane@example.com"
  }
}
```

#### `calendar_get_events`
Retrieves calendar events.

**Parameters:**
- `time_min` (optional): Lower bound for events (RFC3339 format)
- `time_max` (optional): Upper bound for events (RFC3339 format)
- `max_results` (optional): Maximum number of events (default: 10)
- `calendar_id` (optional): Calendar ID (defaults to "primary")

## GitHub Integration

### Available Tools

#### Repository Tools

##### `github_repo_list`
Lists user's repositories.

**Parameters:**
- `visibility` (optional): Repository visibility filter (`all`, `public`, `private`)
- `sort` (optional): Sort order (`created`, `updated`, `pushed`, `full_name`)

**Example:**
```json
{
  "tool": "github_repo_list",
  "parameters": {
    "visibility": "all",
    "sort": "updated"
  }
}
```

##### `github_repo_get`
Gets details of a specific repository.

**Parameters:**
- `owner` (required): Repository owner (username or organization)
- `repo` (required): Repository name

**Example:**
```json
{
  "tool": "github_repo_get",
  "parameters": {
    "owner": "octocat",
    "repo": "Hello-World"
  }
}
```

##### `github_repo_contents`
Lists contents of a repository directory.

**Parameters:**
- `owner` (required): Repository owner
- `repo` (required): Repository name
- `path` (optional): Directory path (defaults to root)

##### `github_repo_file`
Gets the content of a specific file.

**Parameters:**
- `owner` (required): Repository owner
- `repo` (required): Repository name
- `path` (required): File path within the repository

##### `github_repo_config`
Inspects repository configuration files (workflows, package.json, Dockerfile, etc.).

**Parameters:**
- `owner` (required): Repository owner
- `repo` (required): Repository name

#### Issue Tools

##### `github_issue_list`
Lists repository issues.

**Parameters:**
- `owner` (required): Repository owner
- `repo` (required): Repository name
- `state` (optional): Issue state (`open`, `closed`, `all`)
- `labels` (optional): Comma-separated list of labels to filter by

##### `github_issue_create`
Creates a new issue in a repository.

**Parameters:**
- `owner` (required): Repository owner
- `repo` (required): Repository name
- `title` (required): Issue title
- `body` (optional): Issue description/body
- `labels` (optional): Comma-separated list of labels

**Example:**
```json
{
  "tool": "github_issue_create",
  "parameters": {
    "owner": "octocat",
    "repo": "Hello-World",
    "title": "Bug: Login not working",
    "body": "Users are unable to login with their credentials.",
    "labels": "bug,priority:high"
  }
}
```

## Configuration

### Config File Location
- **macOS/Linux**: `~/.config/mcplocker/mcp.json`
- **Windows**: `%USERPROFILE%\.config\mcplocker\mcp.json`

### Config Structure
```json
{
  "auth_server_url": "http://localhost:38741",
  "token": "your-api-token",
  "tools": [
    {
      "name": "calendar_create_event",
      "provider": "google",
      "service": "calendar",
      "enabled": true,
      "authenticated": true
    }
  ]
}
```

## CLI Commands

### Authentication
```bash
mcplocker auth           # Authenticate with server
mcplocker auth login     # Same as above
mcplocker auth logout    # Remove authentication
mcplocker auth status    # Check auth status
```

### Configuration
```bash
mcplocker config set-server <URL>  # Set auth server URL
mcplocker config show             # Show current config
```

### Status
```bash
mcplocker status  # Show overall status (auth + config)
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures (401 errors)
```bash
# Re-authenticate with the server
mcplocker auth
```

#### 2. Cannot Connect to Auth Server
```bash
# Check if the server is running
curl http://localhost:38741/health

# Check your config
mcplocker config show
```

#### 3. Google Services Not Working
- Verify your `.secrets` file is properly configured
- Check that you've enabled the required APIs in Google Cloud Console
- Ensure redirect URIs match exactly in Google Cloud Console

#### 4. Calendar Events Not Creating
- Verify you've connected Google Calendar in the web dashboard
- Check that the Calendar API is enabled in Google Cloud Console
- Ensure your OAuth token has calendar permissions

#### 5. GitHub Services Not Working
- Verify your GitHub OAuth app is properly configured
- Check that `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` environment variables are set
- Ensure the authorization callback URL matches exactly: `http://localhost:38741/api/auth/callback/github`
- Verify you've connected the specific GitHub service (repos/issues) in the web dashboard

#### 6. GitHub API Rate Limiting
- GitHub has rate limits for authenticated requests (5,000 per hour)
- If you hit rate limits, wait for the reset time or use a GitHub App instead of OAuth
- Check your rate limit status in the GitHub API response headers

### Debug Mode
```bash
# Run with debug logging
./bin/authserver --debug
./bin/mcplocker --debug
```

### Log Output
The auth server provides detailed debug logs showing:
- OAuth token validation
- Service connection lookup
- API call execution
- Error details

Example successful calendar event creation:
```
DEBUG: Received proxy tool request - Tool: calendar_create_event
DEBUG: Authenticated user ID: 106018080857844159793
DEBUG: Found service connection for calendar
DEBUG: Service token is valid for calendar
DEBUG: Successfully created calendar event: Team Meeting (ID: abc123...)
```

## Development

### Project Structure
```
mcplocker/
├── cmd/
│   ├── authserver/    # Authentication server
│   └── cli/           # CLI tool
├── internal/
│   ├── auth/          # Auth client
│   ├── config/        # Configuration management
│   ├── mcps/          # MCP provider system
│   │   ├── github/    # GitHub provider
│   │   └── google/    # Google provider
│   └── web/           # Web handlers
└── mcps/              # Legacy MCP implementations
    └── google/
        ├── calendar/  # Calendar implementations
        ├── gmail/     # Gmail implementations
        └── drive/     # Drive implementations
```

### Adding New Services
1. Create service-specific OAuth scopes in `cmd/authserver/main.go`
2. Implement tool handlers in `mcps/<provider>/<service>/`
3. Add tool definitions to available tools list
4. Update web UI for service connection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[License information here]

