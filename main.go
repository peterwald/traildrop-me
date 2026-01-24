package main

import (
	"context"
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

	"golang.org/x/oauth2/clientcredentials"
)

var (
	oauth2Client *http.Client
	templates    *template.Template

	// Environment variables
	tailscaleClientID     string
	tailscaleClientSecret string
	tailnetName           string
	port                  string
)

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
	tailnetName = getEnv("TAILNET_NAME", "")
	port = getEnv("PORT", "8080")

	// Configure OAuth2 client credentials
	config := &clientcredentials.Config{
		ClientID:     tailscaleClientID,
		ClientSecret: tailscaleClientSecret,
		TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
		Scopes:       []string{}, // Scopes are configured in the OAuth client in Tailscale admin
	}

	// Create HTTP client that automatically handles token refresh
	oauth2Client = config.Client(context.Background())

	// Load templates
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if err := templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, "Failed to render template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

func handleDevices(w http.ResponseWriter, r *http.Request) {
	// Fetch devices from Tailscale API using OAuth token
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/tailnet/%s/devices", tailnetName)

	resp, err := oauth2Client.Get(url)
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

func main() {
	// Validate required environment variables
	if tailscaleClientID == "" || tailscaleClientSecret == "" || tailnetName == "" {
		log.Fatal("Missing required environment variables. Please set TAILSCALE_CLIENT_ID, TAILSCALE_CLIENT_SECRET, and TAILNET_NAME")
	}

	// Routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/devices", handleDevices)
	http.HandleFunc("/upload", handleUpload)

	// Start server
	addr := ":" + port
	log.Printf("Starting Taildrop web server on %s", addr)
	log.Printf("Tailnet: %s", tailnetName)
	log.Println("Note: This app is accessible to anyone who can reach it on your network")

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
