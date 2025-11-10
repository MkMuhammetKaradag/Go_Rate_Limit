package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type SignInRequest struct {
	Username string `json:"username"`
}
type SignUpRequest struct {
	Username string `json:"username"`
}
type SignInResponse struct {
	Message string `json:"message"`
	UserID  string `json:"user_id,omitempty"` // Oturum açtıktan sonra verilecek ID
}
type SignUpResponse struct {
	Message string `json:"messasge"`
}

const SessionCookieName = "session_id"

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
	// ... (Metot ve JSON çözümleme kontrolleri)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SignInRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	// ... (Hata kontrolleri)
	if err != nil || req.Username == "" {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// 1. Simüle Edilmiş Kullanıcı ID'si Oluşturma
	// Gerçekte bu, JWT oluşturma veya veritabanından ID alma adımıdır.
	// Örnek: Kullanıcı adının sonuna statik bir ID ekleyelim.
	simulatedUserID := fmt.Sprintf("%s_%d", req.Username, time.Now().Unix()%100) // Örneğin: "ali_45"
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    simulatedUserID,
		Expires:  time.Now().Add(24 * time.Hour), // 24 saat geçerlilik süresi
		HttpOnly: true,                           // Çok önemli güvenlik ayarı!
		Secure:   false,                          // Test ortamı için false, prod için true olmalı!
		Path:     "/",                            // Tüm yollar için geçerli
	})
	// 2. Başarılı Yanıtı Oluşturma
	message := fmt.Sprintf("User %s signed in successfully. Use ID: %s", req.Username, simulatedUserID)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")

	// Yanıt struct'ını kullanarak ID'yi dahil et
	json.NewEncoder(w).Encode(SignInResponse{
		Message: message,
		UserID:  simulatedUserID, // Bu ID istemciye gidiyor!
	})
}
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	// Placeholder for sign-in logic
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req SignUpRequest
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
		log.Println("API_KEY environment variable is required")
	}
	mux.HandleFunc("/signin", corsMiddleware(apiKeyMiddleware(SignInHandler)))
	mux.HandleFunc("/signup", corsMiddleware(apiKeyMiddleware(SignUpHandler)))
	mux.HandleFunc("/hello", corsMiddleware(apiKeyMiddleware(HelloHandler)))
	port := ":8080"
	log.Printf("Auth Service is running  http://localhost%s", port)

	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
