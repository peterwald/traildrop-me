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
)

var (
	oauth2Config *oauth2.Config
	sessions     = make(map[string]*Session)
	sessionMu    sync.RWMutex
	templates    *template.Template

	// Environment variables
	tailscaleClientID     string
	tailscaleClientSecret string
	tailscaleAPIKey       string
	tailnetName           string
	redirectURL           string
	port                  string
)

type Session struct {
	Token     *oauth2.Token
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

func init() {
	// Load environment variables
	tailscaleClientID = getEnv("TAILSCALE_CLIENT_ID", "")
	tailscaleClientSecret = getEnv("TAILSCALE_CLIENT_SECRET", "")
	tailscaleAPIKey = getEnv("TAILSCALE_API_KEY", "")
	tailnetName = getEnv("TAILNET_NAME", "")
	redirectURL = getEnv("REDIRECT_URL", "http://localhost:8080/callback")
	port = getEnv("PORT", "8080")

	// Configure OAuth2
	oauth2Config = &oauth2.Config{
		ClientID:     tailscaleClientID,
		ClientSecret: tailscaleClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"devices:read"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.tailscale.com/api/v2/oauth/authorize",
			TokenURL: "https://login.tailscale.com/api/v2/oauth/token",
		},
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
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 24 hours
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	authenticated := session != nil

	data := struct {
		Authenticated bool
	}{
		Authenticated: authenticated,
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

	// Store state in a temporary session for verification
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	url := oauth2Config.AuthCodeURL(state)
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
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		log.Printf("Token exchange error: %v", err)
		return
	}

	// Create session
	sessionID, err := generateSessionID()
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	setSession(w, sessionID, &Session{
		Token:     token,
		CreatedAt: time.Now(),
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		sessionMu.Lock()
		delete(sessions, cookie.Value)
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
	session := getSession(r)
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch devices from Tailscale API
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", tailnetName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		log.Printf("Request creation error: %v", err)
		return
	}

	req.SetBasicAuth(tailscaleAPIKey, "")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
	session := getSession(r)
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

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
	if tailscaleClientID == "" || tailscaleClientSecret == "" || tailscaleAPIKey == "" || tailnetName == "" {
		log.Fatal("Missing required environment variables. Please set TAILSCALE_CLIENT_ID, TAILSCALE_CLIENT_SECRET, TAILSCALE_API_KEY, and TAILNET_NAME")
	}

	// Routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/devices", requireAuth(handleDevices))
	http.HandleFunc("/upload", requireAuth(handleUpload))

	// Start server
	addr := ":" + port
	log.Printf("Starting Taildrop web server on %s", addr)
	log.Printf("Redirect URL: %s", redirectURL)
	log.Printf("Tailnet: %s", tailnetName)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
