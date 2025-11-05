package models

import (
	"time"
)

// AttackLog - Sızma denemesi log kaydı
type AttackLog struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	IP             string                 `json:"ip"`
	UserAgent      string                 `json:"user_agent"`
	Method         string                 `json:"method"`
	Path           string                 `json:"path"`
	Username       string                 `json:"username"`
	Password       string                 `json:"password"`
	Payload        map[string]interface{} `json:"payload"`
	Headers        map[string]string      `json:"headers"`
	QueryParams    map[string]string      `json:"query_params"`
	ResponseCode   int                    `json:"response_code"`
	Country        string                 `json:"country"`
	City           string                 `json:"city"`
	ISP            string                 `json:"isp"`
	ThreatLevel    string                 `json:"threat_level"`    // low, medium, high, critical
	AttackType     string                 `json:"attack_type"`     // brute_force, sql_injection, xss, etc.
	Fingerprint    string                 `json:"fingerprint"`     // Browser fingerprint
	SessionID      string                 `json:"session_id"`
	ReferrerURL    string                 `json:"referrer_url"`
	IsBot          bool                   `json:"is_bot"`
	BotType        string                 `json:"bot_type"`
	AttemptCount   int                    `json:"attempt_count"`
}

// AttackStats - Saldırı istatistikleri
type AttackStats struct {
	TotalAttempts      int64              `json:"total_attempts"`
	UniqueIPs          int64              `json:"unique_ips"`
	TopAttackers       []IPStats          `json:"top_attackers"`
	AttackTypeBreakdown map[string]int64  `json:"attack_type_breakdown"`
	ThreatLevelBreakdown map[string]int64 `json:"threat_level_breakdown"`
	CountryBreakdown   map[string]int64   `json:"country_breakdown"`
	TimeSeriesData     []TimeSeriesPoint  `json:"time_series_data"`
	CommonPasswords    []PasswordAttempt  `json:"common_passwords"`
	CommonUsernames    []UsernameAttempt  `json:"common_usernames"`
}

// IPStats - IP bazlı istatistikler
type IPStats struct {
	IP           string `json:"ip"`
	AttemptCount int64  `json:"attempt_count"`
	LastSeen     time.Time `json:"last_seen"`
	Country      string `json:"country"`
	ThreatLevel  string `json:"threat_level"`
}

// TimeSeriesPoint - Zaman serisi veri noktası
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Count     int64     `json:"count"`
}

// PasswordAttempt - Şifre deneme istatistiği
type PasswordAttempt struct {
	Password string `json:"password"`
	Count    int64  `json:"count"`
}

// UsernameAttempt - Kullanıcı adı deneme istatistiği
type UsernameAttempt struct {
	Username string `json:"username"`
	Count    int64  `json:"count"`
}

// GeoLocation - Coğrafi konum bilgisi
type GeoLocation struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Organization string `json:"organization"`
}
