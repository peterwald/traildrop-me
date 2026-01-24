package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/github"
)

var (
	tailscaleClient *http.Client
	githubOAuth     *oauth2.Config
	sessions        = make(map[string]*Session)
	sessionMu       sync.RWMutex
	templates       *template.Template
	allowedUsers    map[string]bool

	// Environment variables
	tailscaleClientID     string
	tailscaleClientSecret string
	tailnetName           string
	githubClientID        string
	githubClientSecret    string
	appURL                string
	allowedGitHubUsers    string
	port                  string
)

type Session struct {
	Username  string
	CreatedAt time.Time
}

type Device struct {
	Name      string   `json:"name"`
	Hostname  string   `json:"hostname"`
	Addresses []string `json:"addresses"`
	OS        string   `json:"os"`
}

type DeviceListResponse struct {
	Devices []Device `json:"devices"`
}

type GitHubUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func init() {
	// Load environment variables
	tailscaleClientID = getEnv("TAILSCALE_CLIENT_ID", "")
	tailscaleClientSecret = getEnv("TAILSCALE_CLIENT_SECRET", "")
	tailnetName = getEnv("TAILNET_NAME", "")
	githubClientID = getEnv("GITHUB_CLIENT_ID", "")
	githubClientSecret = getEnv("GITHUB_CLIENT_SECRET", "")
	appURL = getEnv("APP_URL", "http://localhost:8080")
	allowedGitHubUsers = getEnv("ALLOWED_GITHUB_USERS", "")
	port = getEnv("PORT", "8080")

	// Parse allowed users into a map for fast lookup
	allowedUsers = make(map[string]bool)
	if allowedGitHubUsers != "" {
		users := strings.Split(allowedGitHubUsers, ",")
		for _, user := range users {
			trimmed := strings.TrimSpace(user)
			if trimmed != "" {
				allowedUsers[strings.ToLower(trimmed)] = true
			}
		}
		log.Printf("Loaded %d allowed GitHub users", len(allowedUsers))
	} else {
		log.Println("WARNING: No ALLOWED_GITHUB_USERS set - all GitHub users can access this app!")
	}

	// Configure Tailscale OAuth2 client credentials
	tailscaleConfig := &clientcredentials.Config{
		ClientID:     tailscaleClientID,
		ClientSecret: tailscaleClientSecret,
		TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
		Scopes:       []string{}, // Scopes are configured in the OAuth client in Tailscale admin
	}

	// Create HTTP client that automatically handles token refresh
	tailscaleClient = tailscaleConfig.Client(context.Background())

	// Configure GitHub OAuth
	githubOAuth = &oauth2.Config{
		ClientID:     githubClientID,
		ClientSecret: githubClientSecret,
		RedirectURL:  appURL + "/auth/callback",
		Scopes:       []string{"read:user", "user:email"},
		Endpoint:     github.Endpoint,
	}

	// Load templates
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}

	// Start session cleanup goroutine
	go cleanupSessions()
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func cleanupSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		sessionMu.Lock()
		now := time.Now()
		for id, session := range sessions {
			if now.Sub(session.CreatedAt) > 24*time.Hour {
				delete(sessions, id)
			}
		}
		sessionMu.Unlock()
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}

	sessionMu.RLock()
	defer sessionMu.RUnlock()
	return sessions[cookie.Value]
}

func setSession(w http.ResponseWriter, sessionID string, session *Session) {
	sessionMu.Lock()
	sessions[sessionID] = session
	sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(appURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})
}

func isUserAuthorized(username string) bool {
	// If no users are configured, allow all (with warning logged in init)
	if len(allowedUsers) == 0 {
		return true
	}
	// Check if user is in the allowed list (case-insensitive)
	return allowedUsers[strings.ToLower(username)]
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	authenticated := session != nil

	data := struct {
		Authenticated bool
		Username      string
	}{
		Authenticated: authenticated,
		Username:      "",
	}

	if session != nil {
		data.Username = session.Username
	}

	if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateSessionID()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store state in a temporary cookie for verification
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(appURL, "https://"),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	url := githubOAuth.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Verify state
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != stateCookie.Value {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	// Exchange code for token
	code := r.URL.Query().Get("code")
	token, err := githubOAuth.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		log.Printf("Token exchange error: %v", err)
		return
	}

	// Get user info from GitHub
	client := githubOAuth.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		log.Printf("GitHub API error: %v", err)
		return
	}
	defer resp.Body.Close()

	var user GitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		log.Printf("JSON decode error: %v", err)
		return
	}

	// Check if user is authorized
	if !isUserAuthorized(user.Login) {
		log.Printf("Unauthorized login attempt by GitHub user: %s", user.Login)
		http.Error(w, fmt.Sprintf("Access denied. Your GitHub account (%s) is not authorized to access this application. Please contact the administrator.", user.Login), http.StatusForbidden)
		return
	}

	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	setSession(w, sessionID, &Session{
		Username:  user.Login,
		CreatedAt: time.Now(),
	})

	log.Printf("User logged in: %s", user.Login)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		sessionMu.Lock()
		if session, ok := sessions[cookie.Value]; ok {
			log.Printf("User logged out: %s", session.Username)
			delete(sessions, cookie.Value)
		}
		sessionMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleDevices(w http.ResponseWriter, r *http.Request) {
	// Fetch devices from Tailscale API using OAuth token
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", tailnetName)

	resp, err := tailscaleClient.Get(url)
	if err != nil {
		http.Error(w, "Failed to fetch devices", http.StatusInternalServerError)
		log.Printf("Device fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, fmt.Sprintf("Tailscale API error: %s", body), http.StatusInternalServerError)
		log.Printf("Tailscale API error (status %d): %s", resp.StatusCode, body)
		return
	}

	var deviceList DeviceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&deviceList); err != nil {
		http.Error(w, "Failed to decode response", http.StatusInternalServerError)
		log.Printf("JSON decode error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deviceList.Devices)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 500MB)
	if err := r.ParseMultipartForm(500 << 20); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		log.Printf("Form parse error: %v", err)
		return
	}

	// Get device name
	deviceName := r.FormValue("device")
	if deviceName == "" {
		http.Error(w, "Device name is required", http.StatusBadRequest)
		return
	}

	// Sanitize device name (allow only alphanumeric, dash, underscore, and dot)
	deviceName = sanitizeDeviceName(deviceName)
	if deviceName == "" {
		http.Error(w, "Invalid device name", http.StatusBadRequest)
		return
	}

	// Get uploaded file
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		log.Printf("File retrieval error: %v", err)
		return
	}
	defer file.Close()

	// Create temporary file
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, handler.Filename)

	out, err := os.Create(tempFile)
	if err != nil {
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		log.Printf("Temp file creation error: %v", err)
		return
	}

	_, err = io.Copy(out, file)
	out.Close()
	if err != nil {
		os.Remove(tempFile)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		log.Printf("File save error: %v", err)
		return
	}

	// Execute tailscale file cp command
	cmd := exec.Command("tailscale", "file", "cp", tempFile, deviceName+":")
	output, err := cmd.CombinedOutput()

	// Clean up temp file
	os.Remove(tempFile)

	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to send file: %s", output), http.StatusInternalServerError)
		log.Printf("Tailscale file cp error: %v, output: %s", err, output)
		return
	}

	// Log the file transfer
	session := getSession(r)
	username := "unknown"
	if session != nil {
		username = session.Username
	}
	log.Printf("File transfer: %s sent %s to %s", username, handler.Filename, deviceName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("File sent to %s", deviceName),
		"output":  string(output),
	})
}

func sanitizeDeviceName(name string) string {
	// Remove any characters that aren't alphanumeric, dash, underscore, or dot
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := getSession(r)
		if session == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func main() {
	// Validate required environment variables
	if tailscaleClientID == "" || tailscaleClientSecret == "" || tailnetName == "" {
		log.Fatal("Missing required Tailscale environment variables. Please set TAILSCALE_CLIENT_ID, TAILSCALE_CLIENT_SECRET, and TAILNET_NAME")
	}

	if githubClientID == "" || githubClientSecret == "" {
		log.Fatal("Missing required GitHub environment variables. Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET")
	}

	// Routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/auth/login", handleLogin)
	http.HandleFunc("/auth/callback", handleCallback)
	http.HandleFunc("/auth/logout", handleLogout)
	http.HandleFunc("/devices", requireAuth(handleDevices))
	http.HandleFunc("/upload", requireAuth(handleUpload))

	// Start server
	addr := ":" + port
	log.Printf("Starting taildrop.me server on %s", addr)
	log.Printf("Application URL: %s", appURL)
	log.Printf("Tailnet: %s", tailnetName)
	log.Println("GitHub OAuth authentication enabled")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
