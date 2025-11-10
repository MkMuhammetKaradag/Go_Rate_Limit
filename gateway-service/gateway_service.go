package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

// --- SABİT TANIMLAMALAR ---

const InternalGatewayHeader = "X-API-Key"
const InternalGatewaySecret = "gateway-secret-key"
const SessionCookieName = "session_id"

// --- YAPILANDIRMA STRUCT'LARI ---

type RouteConfig struct {
	GlobalLimit rate.Limit
	GlobalBurst int
	UserLimit   rate.Limit
	UserBurst   int
}

type ServiceConfig struct {
	BaseURL    string
	PathPrefix string
}

// --- METRİK YAPISI ---

type Metrics struct {
	mu                  sync.RWMutex
	totalRequests       int64
	rateLimitedRequests map[string]int64 // limitType -> count
	requestsByPath      map[string]int64
	requestsByService   map[string]int64
	lastReset           time.Time
}

func NewMetrics() *Metrics {
	return &Metrics{
		rateLimitedRequests: make(map[string]int64),
		requestsByPath:      make(map[string]int64),
		requestsByService:   make(map[string]int64),
		lastReset:           time.Now(),
	}
}

func (m *Metrics) IncrementTotal() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalRequests++
}

func (m *Metrics) IncrementRateLimit(limitType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rateLimitedRequests[limitType]++
}

func (m *Metrics) IncrementPath(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestsByPath[path]++
}

func (m *Metrics) IncrementService(service string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestsByService[service]++
}

func (m *Metrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uptime := time.Since(m.lastReset)

	return map[string]interface{}{
		"total_requests":        m.totalRequests,
		"rate_limited_requests": m.rateLimitedRequests,
		"requests_by_path":      m.requestsByPath,
		"requests_by_service":   m.requestsByService,
		"uptime_seconds":        uptime.Seconds(),
		"requests_per_second":   float64(m.totalRequests) / uptime.Seconds(),
	}
}

func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalRequests = 0
	m.rateLimitedRequests = make(map[string]int64)
	m.requestsByPath = make(map[string]int64)
	m.requestsByService = make(map[string]int64)
	m.lastReset = time.Now()
}

// --- BASİTLEŞTİRİLMİŞ RATE LIMITER ---

type LimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

type RateLimiter struct {
	limiters sync.Map // map[string]*LimiterEntry
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{}
}

func (rl *RateLimiter) GetLimiter(key string, r rate.Limit, b int) *rate.Limiter {
	now := time.Now()

	if entry, ok := rl.limiters.Load(key); ok {
		limiterEntry := entry.(*LimiterEntry)
		limiterEntry.lastAccess = now
		return limiterEntry.limiter
	}

	newLimiter := rate.NewLimiter(r, b)
	entry := &LimiterEntry{
		limiter:    newLimiter,
		lastAccess: now,
	}

	actual, loaded := rl.limiters.LoadOrStore(key, entry)
	if loaded {
		return actual.(*LimiterEntry).limiter
	}
	return newLimiter
}

func (rl *RateLimiter) StartCleanup(interval, maxAge time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			rl.cleanup(maxAge)
		}
	}()
}

func (rl *RateLimiter) cleanup(maxAge time.Duration) {
	now := time.Now()
	count := 0

	rl.limiters.Range(func(key, value interface{}) bool {
		entry := value.(*LimiterEntry)
		if now.Sub(entry.lastAccess) > maxAge {
			rl.limiters.Delete(key)
			count++
		}
		return true
	})

	if count > 0 {
		log.Printf("🧹 Temizlik: %d kullanılmayan limiter silindi", count)
	}
}

func (rl *RateLimiter) GetStats() map[string]int {
	count := 0
	rl.limiters.Range(func(key, value interface{}) bool {
		count++
		return true
	})

	return map[string]int{
		"active_limiters": count,
	}
}

// --- GENEL DEĞİŞKENLER VE YAPILANDIRMALAR ---

var (
	// Yol Bazlı Limitler (Hem Global hem de User bazlı)
	routeConfigs = map[string]RouteConfig{
		"/auth/signin": {
			GlobalLimit: 5.0 / 60, GlobalBurst: 5,
			UserLimit: 3.0 / 60, UserBurst: 3,
		},
		"/auth/signup": {
			GlobalLimit: 5.0 / 60, GlobalBurst: 5,
			UserLimit: 2.0 / 60, UserBurst: 2,
		},
		"/auth/hello": {
			GlobalLimit: 8.0 / 60, GlobalBurst: 8,
			UserLimit: 4.0 / 60, UserBurst: 4,
		},
		"/users/hello": {
			GlobalLimit: 9.0 / 60, GlobalBurst: 9,
			UserLimit: 5.0 / 60, UserBurst: 5,
		},
		"/users/list": {
			GlobalLimit: 20.0 / 60, GlobalBurst: 10,
			UserLimit: 10.0 / 60, UserBurst: 5,
		},
		"default": {
			GlobalLimit: 20.0 / 60, GlobalBurst: 10,
			UserLimit: 10.0 / 60, UserBurst: 5,
		},
	}

	// Servis Bazlı Kullanıcı Limitleri (Toplamsal - tüm yollar için)
	serviceUserLimits = map[string]RouteConfig{
		"auth": {UserLimit: 3.0 / 60, UserBurst: 3},
		"user": {UserLimit: 50.0 / 60, UserBurst: 20},
	}

	// Servis Bazlı Global Limitler (Toplamsal - tüm yollar için)
	serviceGlobalLimits = map[string]RouteConfig{
		"auth": {GlobalLimit: 5.0 / 60, GlobalBurst: 5},
		"user": {GlobalLimit: 100.0 / 60, GlobalBurst: 30},
	}

	services = map[string]ServiceConfig{
		"auth": {BaseURL: "http://localhost:8080", PathPrefix: "/auth"},
		"user": {BaseURL: "http://localhost:8081", PathPrefix: "/users"},
	}

	rateLimiters = NewRateLimiter()
	metrics      = NewMetrics()

	ProtectedRoutes = map[string]bool{
		"/users/hello": true,
		"/auth/hello":  true,
	}
)

// --- RATE LIMITER YÖNETİMİ ---

func (rl *RateLimiter) getGlobalLimiter(path string) *rate.Limiter {
	config := routeConfigs["default"]
	if c, exists := routeConfigs[path]; exists {
		config = c
	}
	key := "global_path:" + path
	return rl.GetLimiter(key, config.GlobalLimit, config.GlobalBurst)
}

func (rl *RateLimiter) getServiceGlobalLimiter(path string) *rate.Limiter {
	serviceName, _ := getServiceIdentifier(path, "")
	if serviceName == "" {
		return nil
	}

	config := serviceGlobalLimits[serviceName]
	key := "global_service:" + serviceName
	return rl.GetLimiter(key, config.GlobalLimit, config.GlobalBurst)
}

func (rl *RateLimiter) getUserPathLimiter(path, clientIdentifier string) *rate.Limiter {
	config := routeConfigs["default"]
	if c, exists := routeConfigs[path]; exists {
		config = c
	}

	if config.UserLimit == 0 {
		return nil
	}

	key := "user_path:" + clientIdentifier + ":" + path
	return rl.GetLimiter(key, config.UserLimit, config.UserBurst)
}

func getServiceIdentifier(path string, clientIdentifier string) (string, string) {
	var serviceName string

	switch {
	case strings.HasPrefix(path, "/auth/"):
		serviceName = "auth"
	case strings.HasPrefix(path, "/users/"):
		serviceName = "user"
	default:
		return "", ""
	}

	serviceKey := serviceName + ":" + clientIdentifier
	return serviceName, serviceKey
}

func (rl *RateLimiter) getUserLimiter(path, clientIdentifier string) *rate.Limiter {
	serviceName, serviceKey := getServiceIdentifier(path, clientIdentifier)
	if serviceKey == "" {
		return nil
	}

	config := serviceUserLimits[serviceName]
	return rl.GetLimiter(serviceKey, config.UserLimit, config.UserBurst)
}

// --- RATE LIMIT HEADER BİLGİLERİ ---

func setRateLimitHeaders(w http.ResponseWriter, limiter *rate.Limiter, limitType string) {
	if limiter == nil {
		return
	}

	// Bu, token tüketmeden kalan token sayısını tahmin etmenin kaba bir yoludur.
	// Doğru Remaining değeri için Reserve/Cancel kullanmak gerekir, ancak basitlik ve performans için Allow() öncesinde bu kaba tahmin kullanılabilir.
	burst := limiter.Burst()
	tokens := int(limiter.Tokens())

	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", burst))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", tokens))
	w.Header().Set("X-RateLimit-Type", limitType)

	// Retry-After başlığı ekle (saniye cinsinden)
	if tokens <= 0 {
		// Allow() çağrılmadığı için, doğru Delay'i almak için bir Reserve() yapıp iptal etmeliyiz.
		// Bu, Allow() öncesinde çağrıldığında o token'ı tüketmez.
		reservation := limiter.Reserve()
		delay := reservation.Delay()
		reservation.Cancel()
		w.Header().Set("Retry-After", fmt.Sprintf("%.0f", delay.Seconds()))
	}
}

// --- İSTEMCİ KİMLİĞİ ÇIKARIMI VE MIDDLEWARE'LER ---

func extractClientIdentifier(r *http.Request) string {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		return "cookie_user:" + cookie.Value
	}

	ip := r.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = strings.Split(r.RemoteAddr, ":")[0]
	}

	return "ip:" + ip
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-RateLimit-Type, Retry-After")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func AuthorizationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if ProtectedRoutes[path] {
			_, err := r.Cookie(SessionCookieName)

			if err == http.ErrNoCookie {
				log.Printf("🔒 Yetkisiz Erişim Reddedildi: %s (Oturum Yok)", path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Bu kaynağa erişim için oturum açmalısınız.",
				})
				return
			}
		}
		next(w, r)
	}
}

// GÜNCELLENMİŞ rateLimitMiddleware
func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		clientIdentifier := extractClientIdentifier(r)

		// Metrik kaydet
		metrics.IncrementTotal()
		metrics.IncrementPath(path)
		serviceName, _ := getServiceIdentifier(path, clientIdentifier)
		if serviceName != "" {
			metrics.IncrementService(serviceName)
		}

		// Kontrol sırası: En kısıtlayıcı/dar kapsamlı limitten en geniş kapsamlıya doğru gidilmesi tavsiye edilir.

		// 2. KULLANICI BAZLI YOL LİMİTİ (Örn: Bir kullanıcı /auth/signin'e 3 istek/dk)
		userPathLimiter := rateLimiters.getUserPathLimiter(path, clientIdentifier)
		if userPathLimiter != nil {
			setRateLimitHeaders(w, userPathLimiter, "user-path")
			if !userPathLimiter.Allow() {
				metrics.IncrementRateLimit("user-path")
				log.Printf("⛔ Kullanıcı Yol Limiti Aşıldı: %s -> %s", clientIdentifier, path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Rate limit exceeded for this user on this specific path.",
					"type":  "user-path",
				})
				return
			}
		}
		// 1. KULLANICI BAZLI SERVİS TOPLAM LİMİTİ (Örn: Bir kullanıcı Auth servisine toplam 5 istek/dk)
		serviceLimiter := rateLimiters.getUserLimiter(path, clientIdentifier)
		if serviceLimiter != nil {
			setRateLimitHeaders(w, serviceLimiter, "user-service")
			if !serviceLimiter.Allow() {
				metrics.IncrementRateLimit("user-service")
				log.Printf("⛔ Kullanıcı Servis Toplam Limiti Aşıldı: %s -> %s", clientIdentifier, path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Rate limit exceeded for this client/IP across the entire service.",
					"type":  "user-service",
				})
				// Hata alındı, işlem bitti. Daha geniş global kotalar tüketilmedi.
				return
			}
		}
		// 4. YOL BAZLI GLOBAL LİMİT (Örn: /auth/signin'e tüm trafik 5 istek/dk)
		globalLimiter := rateLimiters.getGlobalLimiter(path)
		setRateLimitHeaders(w, globalLimiter, "path-global")
		if !globalLimiter.Allow() {
			metrics.IncrementRateLimit("path-global")
			log.Printf("⛔ Global Yol Limiti Aşıldı: %s", path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Rate limit exceeded globally for this path.",
				"type":  "path-global",
			})
			return
		}
		// 3. SERVİS BAZLI GLOBAL LİMİT (Örn: Auth servisine tüm trafik 10 istek/dk)
		serviceGlobalLimiter := rateLimiters.getServiceGlobalLimiter(path)
		if serviceGlobalLimiter != nil {
			setRateLimitHeaders(w, serviceGlobalLimiter, "service-global")
			if !serviceGlobalLimiter.Allow() {
				metrics.IncrementRateLimit("service-global")
				log.Printf("⛔ Global Servis Toplam Limiti Aşıldı: %s", path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Service aggregate global limit exceeded.",
					"type":  "service-global",
				})
				return
			}
		}
		// Tüm limitler başarılı
		next(w, r)
	}
}

// --- YÖNLENDİRME VE PROXY (Değişmedi) ---

func routeRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	var targetService string

	switch {
	case strings.HasPrefix(path, "/auth/"):
		targetService = "auth"
	case strings.HasPrefix(path, "/users/"):
		targetService = "user"
	default:
		http.Error(w, "Route not found", http.StatusNotFound)
		return
	}

	serviceConfig, exists := services[targetService]
	if !exists {
		http.Error(w, "Service not found", http.StatusServiceUnavailable)
		return
	}

	targetPath := strings.TrimPrefix(path, serviceConfig.PathPrefix)
	targetURL, err := url.Parse(serviceConfig.BaseURL + targetPath)
	if err != nil {
		http.Error(w, "Invalid target URL configuration", http.StatusInternalServerError)
		return
	}

	targetURL.RawQuery = r.URL.RawQuery

	if err := proxyRequest(targetURL.String(), w, r); err != nil {
		log.Printf("❌ Proxy error to %s: %v", targetURL.String(), err)
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
	}
}

func proxyRequest(targetURL string, w http.ResponseWriter, r *http.Request) error {
	bodyBytes, _ := io.ReadAll(r.Body)
	proxyReq, err := http.NewRequest(r.Method, targetURL, io.NopCloser(bytes.NewBuffer(bodyBytes)))
	if err != nil {
		return err
	}

	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}
	}

	proxyReq.Header.Set(InternalGatewayHeader, InternalGatewaySecret)
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)

	if cookieHeader := r.Header.Get("Cookie"); cookieHeader != "" {
		proxyReq.Header.Set("Cookie", cookieHeader)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

func gatewayHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		info := map[string]string{
			"service":  "API Gateway",
			"status":   "Ready",
			"port":     "8082",
			"security": "Cookie-based Authorization Active",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
		return
	}

	routeRequest(w, r)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	stats := metrics.GetStats()
	limiterStats := rateLimiters.GetStats()

	response := map[string]interface{}{
		"metrics":       stats,
		"limiter_stats": limiterStats,
		"timestamp":     time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func metricsResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metrics.Reset()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "metrics reset successfully",
	})
}

func main() {
	mux := http.NewServeMux()

	handler := http.HandlerFunc(gatewayHandler)
	handler = rateLimitMiddleware(handler)
	handler = AuthorizationMiddleware(handler)
	finalHandler := corsMiddleware(handler)

	mux.Handle("/", finalHandler)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/metrics", metricsHandler)
	mux.HandleFunc("/metrics/reset", metricsResetHandler)

	// Temizlik mekanizmasını başlat
	rateLimiters.StartCleanup(5*time.Minute, 10*time.Minute)
	log.Printf("🧹 Temizlik mekanizması başlatıldı (Her 5dk, 10dk+ inaktif)")

	// Periyodik metrik raporu
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			stats := metrics.GetStats()
			limiterStats := rateLimiters.GetStats()
			log.Printf("📊 Metrik Raporu: Toplam İstek=%d, Aktif Limiter=%d, RPS=%.2f",
				stats["total_requests"],
				limiterStats["active_limiters"],
				stats["requests_per_second"])
		}
	}()

	port := ":8082"
	server := &http.Server{
		Addr:         port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("🚀 Gateway Servisi başlatılıyor: http://localhost%s", port)
	log.Printf("\n--- Limit Kuralları (İstek/dk) ---")
	log.Printf("\n🌍 Servis Global (Tüm Kullanıcılar için Servis Toplam):")
	log.Printf(" Auth Servisi: %.1f/dk", serviceGlobalLimits["auth"].GlobalLimit*60)
	log.Printf(" User Servisi: %.1f/dk", serviceGlobalLimits["user"].GlobalLimit*60)

	log.Printf("\n👤 Servis Kullanıcı (Her Kullanıcının Servise Toplam İsteği):")
	log.Printf(" Auth Servisi: %.1f/dk", serviceUserLimits["auth"].UserLimit*60)
	log.Printf(" User Servisi: %.1f/dk", serviceUserLimits["user"].UserLimit*60)

	log.Printf("\n🌍 Yol Bazlı Global (Tüm Kullanıcılar için Yol Toplam):")
	for path, config := range routeConfigs {
		if path != "default" {
			log.Printf(" %s: %.1f/dk", path, config.GlobalLimit*60)
		}
	}

	log.Printf("\n👤 Yol Bazlı Kullanıcı (Her Kullanıcının Yola Özel İsteği):")
	for path, config := range routeConfigs {
		if path != "default" && config.UserLimit > 0 {
			log.Printf(" %s: %.1f/dk", path, config.UserLimit*60)
		}
	}

	log.Printf("\n📢 Korumalı Yollar: %v", ProtectedRoutes)
	log.Printf("\n📊 Yeni Endpoint'ler:")
	log.Printf(" GET /metrics    - Metrik istatistikleri")
	log.Printf(" POST /metrics/reset - Metrikleri sıfırla")
	log.Printf(" GET /health    - Sağlık kontrolü")

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ Gateway sunucusu başlatılırken hata: %v", err)
		}
	}()

	<-sigChan
	log.Println("\n🛑 Shutdown sinyali alındı, graceful shutdown başlatılıyor...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("❌ Shutdown hatası: %v", err)
	}

	log.Println("✅ Gateway servisi düzgün bir şekilde kapatıldı")
}
