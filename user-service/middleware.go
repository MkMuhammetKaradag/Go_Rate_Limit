package main

import (
	"net/http"
	"os"
)

// Middleware'ler
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		allowedOrigins := []string{
			"https://your-frontend.com",
			"http://localhost:3000",
			"http://auth-service:8080",
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

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func apiKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expectedAPIKey := os.Getenv("USER_SERVICE_API_KEY")
		if expectedAPIKey == "" {

			expectedAPIKey = "gateway-secret-key"
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey != expectedAPIKey {
			http.Error(w, "Forbidden: Invalid API Key", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}
