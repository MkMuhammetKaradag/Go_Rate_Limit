package main

import (
	"net/http"
	"os"
	"strings"
)

// CORS middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		allowedOrigins := []string{
			"https://your-frontend.com",
			"http://localhost:3000",
		}

		origin := r.Header.Get("Origin")
		allowed := false

		for _, o := range allowedOrigins {
			if o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// API Key middleware
func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedAPIKey := os.Getenv("API_KEY")
		if expectedAPIKey == "" {
			http.Error(w, "Server configuration error", http.StatusInternalServerError)
			return
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey != expectedAPIKey {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// IP Whitelist middleware
func ipWhitelistMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		allowedIPs := strings.Split(os.Getenv("ALLOWED_IPS"), ",")
		clientIP := strings.Split(r.RemoteAddr, ":")[0]

		if clientIP == "[" {
			clientIP = "127.0.0.1"
		}

		allowed := false
		for _, ip := range allowedIPs {
			if strings.TrimSpace(ip) == clientIP {
				allowed = true
				break
			}
		}

		if !allowed {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
