ackage analyzer

import (
	"crypto/md5"
	"fmt"
	"net"
	"regexp"
	"strings"

	"honeylogger/models"
)

// ThreatAnalyzer - Tehdit analiz edici
type ThreatAnalyzer struct {
	sqlInjectionPatterns []*regexp.Regexp
	xssPatterns          []*regexp.Regexp
	botUserAgents        []string
	commonPasswords      map[string]bool
}

// NewThreatAnalyzer - Yeni analiz edici oluştur
func NewThreatAnalyzer() *ThreatAnalyzer {
	return &ThreatAnalyzer{
		sqlInjectionPatterns: compileSQLPatterns(),
		xssPatterns:          compileXSSPatterns(),
		botUserAgents:        getBotUserAgents(),
		commonPasswords:      getCommonPasswords(),
	}
}

// AnalyzeAttack - Saldırıyı analiz et
func (ta *ThreatAnalyzer) AnalyzeAttack(log *models.AttackLog) {
	log.AttackType = ta.detectAttackType(log)
	log.ThreatLevel = ta.calculateThreatLevel(log)
	log.IsBot, log.BotType = ta.detectBot(log.UserAgent)
	log.Fingerprint = ta.generateFingerprint(log)
}

// detectAttackType - Saldırı tipini tespit et
func (ta *ThreatAnalyzer) detectAttackType(log *models.AttackLog) string {
	payload := fmt.Sprintf("%v %v", log.Username, log.Password)
	
	for _, pattern := range ta.sqlInjectionPatterns {
		if pattern.MatchString(payload) {
			return "sql_injection"
		}
	}

	for _, pattern := range ta.xssPatterns {
		if pattern.MatchString(payload) {
			return "xss"
		}
	}

	if strings.Contains(log.Path, "..") || strings.Contains(log.Path, "etc/passwd") {
		return "path_traversal"
	}

	if log.AttemptCount > 5 {
		return "brute_force"
	}

	if ta.commonPasswords[log.Password] {
		return "credential_stuffing"
	}

	return "reconnaissance"
}

// calculateThreatLevel - Tehdit seviyesini hesapla
func (ta *ThreatAnalyzer) calculateThreatLevel(log *models.AttackLog) string {
	score := 0

	switch log.AttackType {
	case "sql_injection":
		score += 40
	case "xss":
		score += 35
	case "path_traversal":
		score += 30
	case "brute_force":
		score += 20
	case "credential_stuffing":
		score += 15
	}

	if log.AttemptCount > 10 {
		score += 30
	} else if log.AttemptCount > 5 {
		score += 20
	} else if log.AttemptCount > 3 {
		score += 10
	}

	if log.IsBot {
		score += 15
	}

	if ta.isKnownBadIP(log.IP) {
		score += 25
	}

	if score >= 70 {
		return "critical"
	} else if score >= 50 {
		return "high"
	} else if score >= 30 {
		return "medium"
	}
	return "low"
}

// detectBot - Bot tespiti
func (ta *ThreatAnalyzer) detectBot(userAgent string) (bool, string) {
	userAgentLower := strings.ToLower(userAgent)

	botPatterns := map[string]string{
		"bot": "generic_bot", "crawler": "crawler", "spider": "spider",
		"curl": "curl", "wget": "wget", "python": "python_bot",
		"sqlmap": "sqlmap", "nikto": "nikto", "burp": "burp_suite",
	}

	for pattern, botType := range botPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true, botType
		}
	}

	if len(userAgent) < 10 {
		return true, "suspicious"
	}

	return false, ""
}

// generateFingerprint - Browser fingerprint oluştur
func (ta *ThreatAnalyzer) generateFingerprint(log *models.AttackLog) string {
	data := fmt.Sprintf("%s|%s|%s", log.IP, log.UserAgent, log.Method)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// isKnownBadIP - Bilinen kötü IP kontrolü
func (ta *ThreatAnalyzer) isKnownBadIP(ip string) bool {
	badRanges := []string{"185.220.100.0/22", "185.220.101.0/24"}
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	for _, cidr := range badRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ipAddr) {
			return true
		}
	}
	return false
}

func compileSQLPatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)(union.*select)`, `(?i)(select.*from)`, `(?i)(insert.*into)`,
		`(?i)(delete.*from)`, `(?i)(drop.*table)`, `(?i)(or.*1.*=.*1)`,
		`(?i)('.*or.*'.*=.*')`, `(?i)(';.*--)`, `(?i)(benchmark\()`,
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

func compileXSSPatterns() []*regexp.Regexp {
	patterns := []string{
		`(?i)(<script)`, `(?i)(</script>)`, `(?i)(javascript:)`,
		`(?i)(onerror=)`, `(?i)(onload=)`, `(?i)(<iframe)`,
		`(?i)(alert\()`, `(?i)(eval\()`,
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

func getBotUserAgents() []string {
	return []string{"bot", "crawler", "spider", "curl", "wget", "sqlmap", "nikto"}
}

func getCommonPasswords() map[string]bool {
	passwords := []string{
		"123456", "password", "12345678", "qwerty", "admin",
		"root", "toor", "pass", "test", "111111",
	}
	passwordMap := make(map[string]bool)
	for _, p := range passwords {
		passwordMap[p] = true
	}
	return passwordMap
}
