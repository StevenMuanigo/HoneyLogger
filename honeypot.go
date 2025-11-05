package honeypot

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"honeylogger/analyzer"
	"honeylogger/logger"
	"honeylogger/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// HoneyPot - Ana honeypot sistemi
type HoneyPot struct {
	elasticLogger   *logger.ElasticLogger
	threatAnalyzer  *analyzer.ThreatAnalyzer
	ipAttempts      map[string]*IPAttempts
	mu              sync.RWMutex
}

// IPAttempts - IP bazlı deneme sayacı
type IPAttempts struct {
	Count     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// NewHoneyPot - Yeni honeypot oluştur
func NewHoneyPot(elasticLogger *logger.ElasticLogger) *HoneyPot {
	return &HoneyPot{
		elasticLogger:  elasticLogger,
		threatAnalyzer: analyzer.NewThreatAnalyzer(),
		ipAttempts:     make(map[string]*IPAttempts),
	}
}

// FakeAdminPanelHandler - Sahte admin panel
func (hp *HoneyPot) FakeAdminPanelHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "admin_login.html", gin.H{
		"title": "Admin Panel - Login",
	})
}

// LoginAttemptHandler - Login denemesini logla
func (hp *HoneyPot) LoginAttemptHandler(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")
	ip := c.ClientIP()

	// Deneme sayısını güncelle
	attemptCount := hp.updateAttemptCount(ip)

	// Attack log oluştur
	attackLog := &models.AttackLog{
		ID:           uuid.New().String(),
		IP:           ip,
		UserAgent:    c.GetHeader("User-Agent"),
		Method:       c.Request.Method,
		Path:         c.Request.URL.Path,
		Username:     username,
		Password:     password,
		Payload:      hp.extractPayload(c),
		Headers:      hp.extractHeaders(c),
		QueryParams:  hp.extractQueryParams(c),
		ResponseCode: http.StatusUnauthorized,
		ReferrerURL:  c.GetHeader("Referer"),
		SessionID:    hp.getSessionID(c),
		AttemptCount: attemptCount,
	}

	// Tehdit analizi
	hp.threatAnalyzer.AnalyzeAttack(attackLog)

	// Elasticsearch'e logla
	go hp.elasticLogger.LogAttack(attackLog)

	// Sahte gecikme (gerçekçi görünsün)
	time.Sleep(time.Duration(500+attackLog.AttemptCount*100) * time.Millisecond)

	// Sahte hata mesajı döndür
	c.HTML(http.StatusUnauthorized, "admin_login.html", gin.H{
		"error": "Invalid credentials. Please try again.",
		"title": "Admin Panel - Login",
	})
}

// DashboardHandler - Sahte dashboard
func (hp *HoneyPot) DashboardHandler(c *gin.Context) {
	ip := c.ClientIP()
	
	attackLog := &models.AttackLog{
		ID:           uuid.New().String(),
		IP:           ip,
		UserAgent:    c.GetHeader("User-Agent"),
		Method:       c.Request.Method,
		Path:         c.Request.URL.Path,
		ResponseCode: http.StatusOK,
		AttemptCount: hp.updateAttemptCount(ip),
	}

	hp.threatAnalyzer.AnalyzeAttack(attackLog)
	go hp.elasticLogger.LogAttack(attackLog)

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"username": "admin",
		"message":  "Access Restricted - Logging all activities",
	})
}

// APIEndpointHandler - Sahte API endpoint
func (hp *HoneyPot) APIEndpointHandler(c *gin.Context) {
	ip := c.ClientIP()
	
	attackLog := &models.AttackLog{
		ID:           uuid.New().String(),
		IP:           ip,
		UserAgent:    c.GetHeader("User-Agent"),
		Method:       c.Request.Method,
		Path:         c.Request.URL.Path,
		Payload:      hp.extractPayload(c),
		Headers:      hp.extractHeaders(c),
		QueryParams:  hp.extractQueryParams(c),
		ResponseCode: http.StatusForbidden,
		AttemptCount: hp.updateAttemptCount(ip),
	}

	hp.threatAnalyzer.AnalyzeAttack(attackLog)
	go hp.elasticLogger.LogAttack(attackLog)

	c.JSON(http.StatusForbidden, gin.H{
		"error":   "Access denied",
		"code":    403,
		"message": "Insufficient permissions",
	})
}

// updateAttemptCount - IP deneme sayısını güncelle
func (hp *HoneyPot) updateAttemptCount(ip string) int {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if attempts, exists := hp.ipAttempts[ip]; exists {
		attempts.Count++
		attempts.LastSeen = time.Now()
		return attempts.Count
	}

	hp.ipAttempts[ip] = &IPAttempts{
		Count:     1,
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
	return 1
}

// extractPayload - Request payload'ı çıkar
func (hp *HoneyPot) extractPayload(c *gin.Context) map[string]interface{} {
	payload := make(map[string]interface{})
	
	c.Request.ParseForm()
	for key, values := range c.Request.PostForm {
		if len(values) > 0 {
			payload[key] = values[0]
		}
	}

	for key, values := range c.Request.Form {
		if len(values) > 0 {
			payload[key] = values[0]
		}
	}

	return payload
}

// extractHeaders - Header'ları çıkar
func (hp *HoneyPot) extractHeaders(c *gin.Context) map[string]string {
	headers := make(map[string]string)
	for key, values := range c.Request.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}
	return headers
}

// extractQueryParams - Query parametrelerini çıkar
func (hp *HoneyPot) extractQueryParams(c *gin.Context) map[string]string {
	params := make(map[string]string)
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}
	return params
}

// getSessionID - Session ID al
func (hp *HoneyPot) getSessionID(c *gin.Context) string {
	if cookie, err := c.Cookie("session_id"); err == nil {
		return cookie
	}
	sessionID := uuid.New().String()
	c.SetCookie("session_id", sessionID, 3600, "/", "", false, true)
	return sessionID
}

// StatsHandler - İstatistikleri göster
func (hp *HoneyPot) StatsHandler(c *gin.Context) {
	timeRange := c.DefaultQuery("range", "24h")
	
	stats, err := hp.elasticLogger.GetStats(timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("İstatistik alınamadı: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}

// CleanupOldAttempts - Eski denemeleri temizle
func (hp *HoneyPot) CleanupOldAttempts() {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			hp.mu.Lock()
			now := time.Now()
			for ip, attempts := range hp.ipAttempts {
				if now.Sub(attempts.LastSeen) > 24*time.Hour {
					delete(hp.ipAttempts, ip)
				}
			}
			hp.mu.Unlock()
		}
	}()
}
