package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

type SıgnInRequest struct {
	Username string `json:"username"`
}
type SıgnUpRequest struct {
	Username string `json:"username"`
}
type SignInResponse struct {
	Message string `json:"messasge"`
}
type SignUpResponse struct {
	Message string `json:"messasge"`
}

// -------------------HANDLERS-------------------//
func HelloHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hello, This is Auth Service!")
	//w.Write([]byte("Hello, auth service!"))
}

func SignInHandler(w http.ResponseWriter, r *http.Request) {
	// Placeholder for sign-in logic
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SıgnInRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	message := fmt.Sprintf("User %s signed in successfully", req.Username)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SignInResponse{Message: message})

}
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	// Placeholder for sign-in logic
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SıgnUpRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	message := fmt.Sprintf("User %s signup in successfully", req.Username)
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SignUpResponse{Message: message})

}

//-------------------MAIN FUNCTION-------------------//

func main() {
	mux := http.NewServeMux()

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("API_KEY environment variable is required")
	}
	mux.HandleFunc("/signin", corsMiddleware(SignInHandler))
	mux.HandleFunc("/signup", corsMiddleware(SignUpHandler))
	mux.HandleFunc("/hello", corsMiddleware(HelloHandler))
	port := ":8080"
	log.Printf("Auth Service is running  http://localhost%s", port)

	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
