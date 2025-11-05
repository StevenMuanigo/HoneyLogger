package main

import (
	"fmt"
	"log"

	"honeylogger/honeypot"
	"honeylogger/logger"

	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("🔒 HoneyLogger - Sızma Analiz Sistemi Başlatılıyor...")

	// Elasticsearch bağlantısı
	elasticLogger, err := logger.NewElasticLogger(
		[]string{"http://localhost:9200"},
		"honeylogger-attacks",
	)
	if err != nil {
		log.Printf("  Elasticsearch bağlantısı kurulamadı: %v", err)
		log.Println(" Loglar sadece konsola yazılacak...")
	} else {
		log.Println(" Elasticsearch bağlantısı başarılı")
	}

	// HoneyPot oluştur
	hp := honeypot.NewHoneyPot(elasticLogger)
	hp.CleanupOldAttempts()

	// Gin router
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Template'leri yükle
	r.LoadHTMLGlob("templates/*")

	// Static files (eğer varsa)
	r.Static("/static", "./static")

	//  HONEYPOT ROUTES - Sahte Admin Panel
	r.GET("/admin", hp.FakeAdminPanelHandler)
	r.GET("/admin/login", hp.FakeAdminPanelHandler)
	r.POST("/admin/login", hp.LoginAttemptHandler)
	r.GET("/admin/dashboard", hp.DashboardHandler)

	// Yaygın admin path'leri (tuzaklar)
	adminPaths := []string{
		"/administrator", "/wp-admin", "/cpanel", "/phpmyadmin",
		"/admin-panel", "/control-panel", "/admin-console",
		"/management", "/backend", "/cms", "/portal",
	}
	
	for _, path := range adminPaths {
		r.GET(path, hp.FakeAdminPanelHandler)
		r.POST(path, hp.LoginAttemptHandler)
	}

	// 🎯 SAHTE API ENDPOINTS
	r.GET("/api/users", hp.APIEndpointHandler)
	r.POST("/api/users", hp.APIEndpointHandler)
	r.GET("/api/admin", hp.APIEndpointHandler)
	r.POST("/api/login", hp.APIEndpointHandler)
	r.GET("/api/config", hp.APIEndpointHandler)
	r.GET("/api/database", hp.APIEndpointHandler)

	// 📊 İSTATİSTİK ENDPOINT (Gerçek - Sadece localhost)
	r.GET("/stats", func(c *gin.Context) {
		// Sadece localhost'tan erişime izin ver
		if c.ClientIP() != "127.0.0.1" && c.ClientIP() != "::1" {
			c.JSON(403, gin.H{"error": "Access denied"})
			return
		}
		hp.StatsHandler(c)
	})

	// Ana sayfa - Masum görünümlü
	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{
			"title": "Welcome",
		})
	})

	// 404 handler - Tüm bilinmeyen path'ler için
	r.NoRoute(func(c *gin.Context) {
		ip := c.ClientIP()
		log.Printf("🔍 Unknown path accessed: %s from %s", c.Request.URL.Path, ip)
		c.JSON(404, gin.H{
			"error":   "Not found",
			"message": "The requested resource does not exist",
		})
	})

	// Sunucuyu başlat
	port := ":8080"
	fmt.Println("\n HoneyLogger çalışıyor!")
	fmt.Printf(" Sahte Admin Panel: http://localhost%s/admin\n", port)
	fmt.Printf(" İstatistikler: http://localhost%s/stats\n", port)
	fmt.Println(" Tüm sızma denemeleri loglanıyor...")
	fmt.Println("⚡ Ctrl+C ile durdurun\n")

	if err := r.Run(port); err != nil {
		log.Fatalf(" Sunucu başlatılamadı: %v", err)
	}
}
