# GitHub MCP Provider

This directory contains the GitHub MCP (Model Context Protocol) provider for MCPLocker, enabling integration with GitHub repositories and issues.

## Features

- **Repository Management**: List, browse, and inspect repositories
- **File Access**: Read repository contents and individual files
- **Configuration Inspection**: Analyze repository configurations (workflows, package.json, Dockerfile, etc.)
- **Issue Management**: List and create GitHub issues
- **OAuth2 Authentication**: Secure token-based access to GitHub API

## Available Tools

### Repository Tools

- `github_repo_list` - List user's repositories
- `github_repo_get` - Get details of a specific repository
- `github_repo_contents` - Browse repository directory contents
- `github_repo_file` - Read specific file contents
- `github_repo_config` - Inspect repository configuration files

### Issue Tools

- `github_issue_list` - List repository issues
- `github_issue_create` - Create new issues in repositories

## Setup Instructions

### 1. Create GitHub OAuth App

1. **Navigate to GitHub Settings**
   - Go to [GitHub Developer Settings](https://github.com/settings/developers)
   - Or manually navigate: GitHub Settings → Developer settings → OAuth Apps

2. **Create New OAuth App**
   - Click "New OAuth App"
   - Fill in the required information:
     - **Application name**: `MCPLocker` (or your preferred name)
     - **Homepage URL**: `http://localhost:38741`
     - **Application description**: (optional) "MCPLocker GitHub integration"
     - **Authorization callback URL**: `http://localhost:38741/api/auth/callback/github`

3. **Save Application**
   - Click "Register application"
   - You'll be redirected to your new OAuth app's settings page

### 2. Get OAuth Credentials

1. **Copy Client ID**
   - On your OAuth app's settings page, copy the "Client ID"

2. **Generate Client Secret**
   - Click "Generate a new client secret"
   - **Important**: Copy the client secret immediately - it won't be shown again
   - Store it securely

### 3. Configure Environment Variables

Set the following environment variables with your OAuth app credentials:

```bash
export GITHUB_CLIENT_ID="your-github-client-id-here"
export GITHUB_CLIENT_SECRET="your-github-client-secret-here"
```

#### Option 1: Set in Shell Profile
Add to your `~/.bashrc`, `~/.zshrc`, or equivalent:

```bash
# GitHub OAuth Configuration for MCPLocker
export GITHUB_CLIENT_ID="ghp_xxxxxxxxxxxxxxxxxxxx"
export GITHUB_CLIENT_SECRET="ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

#### Option 2: Environment File
Create a `.env` file (not committed to git):

```bash
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
```

#### Option 3: Runtime Configuration
Set variables when starting the auth server:

```bash
GITHUB_CLIENT_ID="your-id" GITHUB_CLIENT_SECRET="your-secret" ./bin/authserver
```

### 4. Start MCPLocker Services

1. **Start Auth Server**
   ```bash
   ./bin/authserver
   ```

2. **Verify GitHub Configuration**
   - The server logs should show: `Registered MCP providers: [google, github]`
   - No errors about missing GitHub configuration

### 5. Connect GitHub Services

1. **Open Web Dashboard**
   - Navigate to `http://localhost:38741`
   - Sign in with your Google account (required for user management)

2. **Connect GitHub Services**
   - Go to the "Services" page
   - Find the "GitHub Services" section
   - Click "Configure" on either:
     - **GitHub Repositories** - For repository access
     - **GitHub Issues** - For issue management

3. **Authorize GitHub Access**
   - You'll be redirected to GitHub
   - Review the requested permissions
   - Click "Authorize" to grant access
   - You'll be redirected back to MCPLocker

## OAuth Scopes

The GitHub provider requests the following OAuth scopes:

### Repository Service (`repo`, `read:user`)
- **`repo`**: Full control of private repositories
  - Read and write access to code, issues, pull requests, etc.
  - Required for repository browsing and file access
- **`read:user`**: Read user profile data
  - Access to public profile information
  - Required for user identification

### Issues Service (`repo`, `read:user`)
- **`repo`**: Access to repository issues
  - Create, read, and manage issues
  - Required for issue management
- **`read:user`**: Read user profile data
  - Access to public profile information
  - Required for user identification

## Security Considerations

- **Client Secret Protection**: Never commit your client secret to version control
- **Scope Limitations**: Only request the minimum required scopes
- **Token Storage**: MCPLocker stores OAuth tokens securely in memory (consider database storage for production)
- **Rate Limiting**: GitHub enforces rate limits (5,000 requests/hour for authenticated users)

## Troubleshooting

### Configuration Issues

**Error: "GitHub OAuth not configured"**
- Verify `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` environment variables are set
- Check that variables are exported and available to the auth server process

**Error: "Invalid state parameter"**
- Ensure the callback URL in your GitHub OAuth app matches exactly: `http://localhost:38741/api/auth/callback/github`
- Try clearing browser cookies and re-attempting authorization

### Authorization Issues

**Error: "Service github:repos not authenticated"**
- Complete the GitHub authorization flow in the web dashboard
- Verify you've connected the specific service (repos or issues)
- Check that OAuth scopes include required permissions

**Error: "GitHub API error: 401"**
- Your token may have expired or been revoked
- Disconnect and reconnect the GitHub service
- Verify your GitHub OAuth app is still active

### Rate Limiting

**Error: "API rate limit exceeded"**
- GitHub allows 5,000 requests per hour for authenticated users
- Wait for the rate limit to reset (check response headers for reset time)
- Consider implementing request caching for production use

## Development

### Adding New GitHub Tools

1. **Add tool function** in `tools.go`
2. **Update tool router** in `ExecuteGitHubTool()`
3. **Add tool schema** in CLI (`cmd/cli/main.go`)
4. **Update available tools** in auth server
5. **Test with GitHub API** using your OAuth token

### File Structure

```
internal/mcps/github/
├── README.md       # This file
├── provider.go     # GitHub OAuth provider implementation
└── tools.go        # GitHub API tool implementations
```

### Dependencies

- `golang.org/x/oauth2` - OAuth2 client implementation
- GitHub API v3 (REST API) - No additional Go library required

## API Reference

### Repository Tools

#### List Repositories
```json
{
  "tool": "github_repo_list",
  "parameters": {
    "visibility": "all",     // all, public, private
    "sort": "updated"        // created, updated, pushed, full_name
  }
}
```

#### Get Repository
```json
{
  "tool": "github_repo_get", 
  "parameters": {
    "owner": "octocat",
    "repo": "Hello-World"
  }
}
```

#### Browse Contents
```json
{
  "tool": "github_repo_contents",
  "parameters": {
    "owner": "octocat",
    "repo": "Hello-World",
    "path": "src"              // optional, defaults to root
  }
}
```

#### Read File
```json
{
  "tool": "github_repo_file",
  "parameters": {
    "owner": "octocat", 
    "repo": "Hello-World",
    "path": "README.md"
  }
}
```

### Issue Tools

#### List Issues
```json
{
  "tool": "github_issue_list",
  "parameters": {
    "owner": "octocat",
    "repo": "Hello-World", 
    "state": "open",           // open, closed, all
    "labels": "bug,enhancement" // comma-separated
  }
}
```

#### Create Issue
```json
{
  "tool": "github_issue_create",
  "parameters": {
    "owner": "octocat",
    "repo": "Hello-World",
    "title": "Bug: Login not working",
    "body": "Description of the issue...",
    "labels": "bug,priority:high"
  }
}
```

## License

This GitHub MCP provider is part of MCPLocker and follows the same license terms.