package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

type HelloResponse struct {
	Message string `json:"message"`
}

type UsersResponse struct {
	Users []User `json:"users"`
}

// Handlers
func HelloHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := HelloResponse{
		Message: "Hello, this is user service!",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func UsersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	users := []User{
		{
			ID:       1,
			Username: "john_doe",
			Email:    "john@example.com",
			Name:     "John Doe",
		},
		{
			ID:       2,
			Username: "jane_smith",
			Email:    "jane@example.com",
			Name:     "Jane Smith",
		},
		{
			ID:       3,
			Username: "bob_wilson",
			Email:    "bob@example.com",
			Name:     "Bob Wilson",
		},
	}

	response := UsersResponse{
		Users: users,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Health check handler
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "user-service",
	})
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/hello", corsMiddleware(apiKeyMiddleware(HelloHandler)))
	mux.HandleFunc("/users", corsMiddleware(apiKeyMiddleware(UsersHandler)))
	// mux.HandleFunc("/health", corsMiddleware(apiKeyMiddleware(HealthHandler)))

	// Port ayarı
	port := ":8081"
	log.Printf("User Service is running on http://localhost%s", port)

	if envPort := os.Getenv("USER_SERVICE_PORT"); envPort != "" {
		port = ":" + envPort
	}

	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
