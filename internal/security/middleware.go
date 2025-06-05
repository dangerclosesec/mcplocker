package security

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// SecurityHeaders middleware adds security headers to responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		
		// Enable XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		// Force HTTPS in production
		if os.Getenv("ENV") == "production" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		
		// Content Security Policy - Allow Tailwind CSS and other CDN resources
		var csp string
		if os.Getenv("ENV") == "production" {
			csp = "default-src 'self'; " +
				"script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " +
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
				"img-src 'self' data: https:; " +
				"font-src 'self' https://fonts.gstatic.com; " +
				"connect-src 'self'; " +
				"frame-ancestors 'none'"
		} else {
			// More permissive CSP for development - allow common CDNs including Tailwind
			csp = "default-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
				"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; " +
				"style-src 'self' 'unsafe-inline' https: data:; " +
				"img-src 'self' data: https: http:; " +
				"font-src 'self' https: data:; " +
				"connect-src 'self' ws: wss:; " +
				"frame-ancestors 'none'"
		}
		w.Header().Set("Content-Security-Policy", csp)
		
		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Remove server information
		w.Header().Set("Server", "MCPLocker")
		
		next.ServeHTTP(w, r)
	})
}

// RequireHTTPS middleware redirects HTTP requests to HTTPS in production
func RequireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only enforce HTTPS in production
		if os.Getenv("ENV") == "production" {
			// Check various headers that might indicate the original protocol
			proto := r.Header.Get("X-Forwarded-Proto")
			if proto == "" {
				proto = r.Header.Get("X-Forwarded-Protocol")
			}
			if proto == "" {
				proto = r.Header.Get("X-Url-Scheme")
			}
			
			// If we're behind a proxy and it's not HTTPS, redirect
			if proto != "" && proto != "https" {
				redirectURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.String())
				http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
				return
			}
			
			// If we're not behind a proxy and TLS is not enabled, redirect
			if proto == "" && r.TLS == nil {
				redirectURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.String())
				http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)
				return
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware provides basic rate limiting
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		clientIP := getClientIP(r)
		
		// Check rate limit (basic implementation)
		if isRateLimited(clientIP) {
			// Log rate limit violation
			if GlobalAuditLogger != nil {
				GlobalAuditLogger.LogRateLimitExceeded("", "", clientIP)
			}
			
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

// CSRFProtectionMiddleware provides CSRF protection for state-changing operations
func CSRFProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only check CSRF for state-changing methods
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
			// Skip CSRF for API endpoints with Bearer token
			if strings.HasPrefix(r.URL.Path, "/api/") && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				next.ServeHTTP(w, r)
				return
			}
			
			// Check CSRF token for web requests
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				token = r.FormValue("csrf_token")
			}
			
			// Get expected token from session/cookie
			expectedToken := getCSRFTokenFromSession(r)
			
			if expectedToken == "" || !isValidCSRFToken(token, expectedToken) {
				// Log CSRF violation
				if GlobalAuditLogger != nil {
					GlobalAuditLogger.LogSecurityViolation("", getClientIP(r), "csrf_token_mismatch", "Invalid or missing CSRF token")
				}
				
				http.Error(w, "Forbidden: Invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

// AuditMiddleware logs requests for audit purposes
func AuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		// Process request
		next.ServeHTTP(wrapped, r)
		
		// Log request for audit if it's a sensitive operation
		if isSensitiveEndpoint(r.URL.Path) && GlobalAuditLogger != nil {
			duration := time.Since(start)
			success := wrapped.statusCode < 400
			
			// Extract user info if available (from session or token)
			userID := getUserIDFromRequest(r)
			
			GlobalAuditLogger.LogToolExecution(
				userID,
				extractActionFromPath(r.URL.Path),
				extractServiceFromPath(r.URL.Path),
				getClientIP(r),
				success,
				"",
				duration,
			)
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Helper functions

// getClientIP extracts the real client IP from request headers
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (may contain multiple IPs)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP (original client)
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}
	
	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	
	// Fall back to remote address
	return r.RemoteAddr
}

// isRateLimited checks if the client IP is rate limited (basic implementation)
// In production, this should use a proper rate limiting library like golang.org/x/time/rate
func isRateLimited(clientIP string) bool {
	// TODO: Implement proper rate limiting with Redis or in-memory store
	// This is a placeholder that always returns false
	return false
}

// getCSRFTokenFromSession retrieves CSRF token from session
func getCSRFTokenFromSession(r *http.Request) string {
	// TODO: Implement proper CSRF token retrieval from session
	// This should integrate with your session management
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// isValidCSRFToken validates CSRF token using constant-time comparison
func isValidCSRFToken(provided, expected string) bool {
	if len(provided) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

// isSensitiveEndpoint checks if the endpoint should be audited
func isSensitiveEndpoint(path string) bool {
	sensitiveEndpoints := []string{
		"/api/proxy/tool",
		"/api/auth/",
		"/api/tokens/",
		"/auth/",
	}
	
	for _, endpoint := range sensitiveEndpoints {
		if strings.Contains(path, endpoint) {
			return true
		}
	}
	return false
}

// getUserIDFromRequest extracts user ID from request context or headers
func getUserIDFromRequest(r *http.Request) string {
	// Try to get from context first (set by auth middleware)
	if userID := r.Context().Value("userID"); userID != nil {
		if id, ok := userID.(string); ok {
			return id
		}
	}
	
	// Could also extract from JWT token or session
	// This is a placeholder implementation
	return ""
}

// extractActionFromPath extracts the action/tool name from URL path
func extractActionFromPath(path string) string {
	if strings.Contains(path, "/api/proxy/tool") {
		return "tool_execution"
	}
	if strings.Contains(path, "/api/auth/") {
		return "authentication"
	}
	if strings.Contains(path, "/api/tokens/") {
		return "token_management"
	}
	return "web_request"
}

// extractServiceFromPath extracts the service name from URL path
func extractServiceFromPath(path string) string {
	if strings.Contains(path, "google") {
		return "google"
	}
	if strings.Contains(path, "github") {
		return "github"
	}
	if strings.Contains(path, "slack") {
		return "slack"
	}
	return "web"
}