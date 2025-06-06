package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

//go:embed templates/*
var templatesFS embed.FS

var templates *template.Template

var templateCache = make(map[string]*template.Template)

func init() {
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"dict": func(values ...interface{}) map[string]interface{} {
			dict := make(map[string]interface{})
			for i := 0; i < len(values); i += 2 {
				if i+1 < len(values) {
					dict[values[i].(string)] = values[i+1]
				}
			}
			return dict
		},
	}

	// Parse login template (standalone)
	loginTmpl, err := template.New("login.html").Funcs(funcMap).ParseFS(templatesFS, "templates/login.html")
	if err != nil {
		panic("Failed to parse login template: " + err.Error())
	}
	templateCache["login.html"] = loginTmpl

	// Parse each content template with layout
	contentTemplates := []string{"dashboard.html", "services.html", "tokens.html"}
	for _, tmplName := range contentTemplates {
		tmpl, err := template.New("layout.html").Funcs(funcMap).ParseFS(templatesFS, "templates/layout.html", "templates/"+tmplName)
		if err != nil {
			panic("Failed to parse template " + tmplName + ": " + err.Error())
		}
		templateCache[tmplName] = tmpl
	}
}

// RenderTemplate renders a template with the given data
func RenderTemplate(w http.ResponseWriter, name string, data interface{}) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, exists := templateCache[name]
	if !exists {
		return fmt.Errorf("template not found: %s", name)
	}

	// For login page, execute the login template directly (standalone)
	if name == "login.html" {
		return tmpl.Execute(w, data)
	}

	// For other pages, execute the layout template
	return tmpl.ExecuteTemplate(w, "layout.html", data)
}

// PageData represents common data passed to templates
type PageData struct {
	Title     string
	User      *User
	CSRFToken string
	Flash     string
}

// User represents an authenticated user
type User struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// ServiceData represents data for the services page
type ServiceData struct {
	PageData
	Services []ServiceInfo
}

// ServiceInfo represents information about an MCP service
type ServiceInfo struct {
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	Service       string `json:"service"`
	Enabled       bool   `json:"enabled"`
	Authenticated bool   `json:"authenticated"`
	AuthURL       string `json:"auth_url,omitempty"`
	LastUsed      string `json:"last_used,omitempty"`
}
