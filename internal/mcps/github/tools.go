package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// ExecuteGitHubTool executes GitHub API calls
func ExecuteGitHubTool(toolName string, parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	switch {
	case strings.Contains(toolName, "repo_list") || strings.Contains(toolName, "repos_list"):
		return listRepositories(parameters, token)
	case strings.Contains(toolName, "repo_get") || strings.Contains(toolName, "repos_get"):
		return getRepository(parameters, token)
	case strings.Contains(toolName, "repo_contents") || strings.Contains(toolName, "repos_contents"):
		return getRepositoryContents(parameters, token)
	case strings.Contains(toolName, "repo_file") || strings.Contains(toolName, "repos_file"):
		return getRepositoryFile(parameters, token)
	case strings.Contains(toolName, "repo_config") || strings.Contains(toolName, "repos_config"):
		return getRepositoryConfig(parameters, token)
	case strings.Contains(toolName, "issue_list") || strings.Contains(toolName, "issues_list"):
		return listIssues(parameters, token)
	case strings.Contains(toolName, "issue_create") || strings.Contains(toolName, "issues_create"):
		return createIssue(parameters, token)
	default:
		return nil, fmt.Errorf("unsupported GitHub tool: %s", toolName)
	}
}

// GitHubRepository represents a GitHub repository
type GitHubRepository struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	FullName    string `json:"full_name"`
	Description string `json:"description"`
	Private     bool   `json:"private"`
	HTMLURL     string `json:"html_url"`
	CloneURL    string `json:"clone_url"`
	Language    string `json:"language"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
	Size        int    `json:"size"`
	StarCount   int    `json:"stargazers_count"`
	ForksCount  int    `json:"forks_count"`
}

// GitHubFile represents a file or directory in a repository
type GitHubFile struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Type        string `json:"type"` // "file" or "dir"
	Size        int    `json:"size"`
	DownloadURL string `json:"download_url"`
	HTMLURL     string `json:"html_url"`
}

// GitHubIssue represents a GitHub issue
type GitHubIssue struct {
	ID     int    `json:"id"`
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
	User   struct {
		Login string `json:"login"`
	} `json:"user"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	HTMLURL   string `json:"html_url"`
}

// makeGitHubAPIRequest makes an authenticated request to the GitHub API
func makeGitHubAPIRequest(ctx context.Context, token *oauth2.Token, method, url string, body io.Reader) (*http.Response, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "MCPLocker-GitHub-Connector/1.0")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	
	return resp, nil
}

// listRepositories lists user's repositories
func listRepositories(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	// Build API URL
	url := "https://api.github.com/user/repos"
	
	// Add query parameters
	params := []string{}
	if visibility, ok := parameters["visibility"].(string); ok && visibility != "" {
		params = append(params, "visibility="+visibility)
	}
	if sort, ok := parameters["sort"].(string); ok && sort != "" {
		params = append(params, "sort="+sort)
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}
	
	resp, err := makeGitHubAPIRequest(ctx, token, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s (status: %d)", string(body), resp.StatusCode)
	}
	
	var repos []GitHubRepository
	if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return map[string]interface{}{
		"success":      true,
		"message":      "Repositories retrieved successfully",
		"repositories": repos,
		"total_count":  len(repos),
	}, nil
}

// getRepository gets details of a specific repository
func getRepository(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	owner, ok := parameters["owner"].(string)
	if !ok || owner == "" {
		return nil, fmt.Errorf("owner parameter is required")
	}
	
	repo, ok := parameters["repo"].(string)
	if !ok || repo == "" {
		return nil, fmt.Errorf("repo parameter is required")
	}
	
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	
	resp, err := makeGitHubAPIRequest(ctx, token, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s (status: %d)", string(body), resp.StatusCode)
	}
	
	var repository GitHubRepository
	if err := json.NewDecoder(resp.Body).Decode(&repository); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return map[string]interface{}{
		"success":    true,
		"message":    "Repository details retrieved successfully",
		"repository": repository,
	}, nil
}

// getRepositoryContents lists contents of a repository directory
func getRepositoryContents(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	owner, ok := parameters["owner"].(string)
	if !ok || owner == "" {
		return nil, fmt.Errorf("owner parameter is required")
	}
	
	repo, ok := parameters["repo"].(string)
	if !ok || repo == "" {
		return nil, fmt.Errorf("repo parameter is required")
	}
	
	path := ""
	if p, ok := parameters["path"].(string); ok {
		path = p
	}
	
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	
	resp, err := makeGitHubAPIRequest(ctx, token, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s (status: %d)", string(body), resp.StatusCode)
	}
	
	var contents []GitHubFile
	if err := json.NewDecoder(resp.Body).Decode(&contents); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return map[string]interface{}{
		"success":  true,
		"message":  "Repository contents retrieved successfully",
		"contents": contents,
		"path":     path,
	}, nil
}

// getRepositoryFile gets the content of a specific file
func getRepositoryFile(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	owner, ok := parameters["owner"].(string)
	if !ok || owner == "" {
		return nil, fmt.Errorf("owner parameter is required")
	}
	
	repo, ok := parameters["repo"].(string)
	if !ok || repo == "" {
		return nil, fmt.Errorf("repo parameter is required")
	}
	
	path, ok := parameters["path"].(string)
	if !ok || path == "" {
		return nil, fmt.Errorf("path parameter is required")
	}
	
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	
	resp, err := makeGitHubAPIRequest(ctx, token, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s (status: %d)", string(body), resp.StatusCode)
	}
	
	var file struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		Size        int    `json:"size"`
		Content     string `json:"content"`
		Encoding    string `json:"encoding"`
		DownloadURL string `json:"download_url"`
		HTMLURL     string `json:"html_url"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&file); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return map[string]interface{}{
		"success":      true,
		"message":      "File content retrieved successfully",
		"name":         file.Name,
		"path":         file.Path,
		"size":         file.Size,
		"content":      file.Content,
		"encoding":     file.Encoding,
		"download_url": file.DownloadURL,
		"html_url":     file.HTMLURL,
	}, nil
}

// getRepositoryConfig gets repository configuration files
func getRepositoryConfig(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	owner, ok := parameters["owner"].(string)
	if !ok || owner == "" {
		return nil, fmt.Errorf("owner parameter is required")
	}
	
	repo, ok := parameters["repo"].(string)
	if !ok || repo == "" {
		return nil, fmt.Errorf("repo parameter is required")
	}
	
	// Get repository details first
	repoResult, err := getRepository(parameters, token)
	if err != nil {
		return nil, err
	}
	
	// Check for common configuration files
	configFiles := []string{
		".github/workflows",
		"package.json",
		"pom.xml",
		"Dockerfile",
		"docker-compose.yml",
		".gitignore",
		"README.md",
		".github/dependabot.yml",
		".github/CODEOWNERS",
	}
	
	foundConfigs := []map[string]interface{}{}
	
	for _, configPath := range configFiles {
		configParams := map[string]interface{}{
			"owner": owner,
			"repo":  repo,
			"path":  configPath,
		}
		
		result, err := getRepositoryContents(configParams, token)
		if err == nil {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if success, ok := resultMap["success"].(bool); ok && success {
					foundConfigs = append(foundConfigs, map[string]interface{}{
						"type":     "config_file",
						"path":     configPath,
						"contents": resultMap["contents"],
					})
				}
			}
		}
	}
	
	return map[string]interface{}{
		"success":     true,
		"message":     "Repository configuration retrieved successfully",
		"repository":  repoResult,
		"config_files": foundConfigs,
	}, nil
}

// listIssues lists repository issues
func listIssues(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	owner, ok := parameters["owner"].(string)
	if !ok || owner == "" {
		return nil, fmt.Errorf("owner parameter is required")
	}
	
	repo, ok := parameters["repo"].(string)
	if !ok || repo == "" {
		return nil, fmt.Errorf("repo parameter is required")
	}
	
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)
	
	// Add query parameters
	params := []string{}
	if state, ok := parameters["state"].(string); ok && state != "" {
		params = append(params, "state="+state)
	}
	if labels, ok := parameters["labels"].(string); ok && labels != "" {
		params = append(params, "labels="+labels)
	}
	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}
	
	resp, err := makeGitHubAPIRequest(ctx, token, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s (status: %d)", string(body), resp.StatusCode)
	}
	
	var issues []GitHubIssue
	if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return map[string]interface{}{
		"success":     true,
		"message":     "Issues retrieved successfully",
		"issues":      issues,
		"total_count": len(issues),
	}, nil
}

// createIssue creates a new issue in a repository
func createIssue(parameters map[string]interface{}, token *oauth2.Token) (interface{}, error) {
	ctx := context.Background()
	
	owner, ok := parameters["owner"].(string)
	if !ok || owner == "" {
		return nil, fmt.Errorf("owner parameter is required")
	}
	
	repo, ok := parameters["repo"].(string)
	if !ok || repo == "" {
		return nil, fmt.Errorf("repo parameter is required")
	}
	
	title, ok := parameters["title"].(string)
	if !ok || title == "" {
		return nil, fmt.Errorf("title parameter is required")
	}
	
	body := ""
	if b, ok := parameters["body"].(string); ok {
		body = b
	}
	
	issueData := map[string]interface{}{
		"title": title,
		"body":  body,
	}
	
	if labels, ok := parameters["labels"].(string); ok && labels != "" {
		labelList := strings.Split(labels, ",")
		for i, label := range labelList {
			labelList[i] = strings.TrimSpace(label)
		}
		issueData["labels"] = labelList
	}
	
	jsonData, err := json.Marshal(issueData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issue data: %w", err)
	}
	
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)
	
	resp, err := makeGitHubAPIRequest(ctx, token, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s (status: %d)", string(body), resp.StatusCode)
	}
	
	var issue GitHubIssue
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	return map[string]interface{}{
		"success": true,
		"message": "Issue created successfully",
		"issue":   issue,
	}, nil
}