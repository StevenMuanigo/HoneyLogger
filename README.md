# HoneyLogger

# HoneyLogger - Intrusion Analysis System

**Professional Honeypot & Attack Analysis Platform**

## Features

### Core Features
- **Fake Admin Panel**: Realistic login page
- **Smart Threat Analysis**: SQL Injection, XSS, Brute Force detection
- **Real-time Logging**: Elasticsearch integration
- **Kibana Dashboard**: Visual analysis and reporting
- **Bot Detection**: 15+ bot pattern recognition
- **IP Tracking**: Attempt counter and fingerprinting
- **Geolocation Analysis**: Country/ISP based tracking

### Advanced Features
- **Attack Types**: SQL Injection, XSS, Path Traversal, Brute Force, Credential Stuffing
- **Threat Levels**: Low, Medium, High, Critical
- **Session Tracking**: Browser fingerprinting
- **Payload Analysis**: POST/GET parameters
- **Header Inspection**: User-Agent, Referer tracking
- **Auto Cleanup**: Automatic cleanup of old records

## Installation

### Requirements
- Go 1.21+
- Elasticsearch 8.x
- Kibana 8.x (optional)
- Docker & Docker Compose (optional)

### Quick Start

#### Windows:
```batch
# 1. Build
build.bat

# 2. Run
run.bat
```

#### With Docker:
```bash
docker-compose up -d
```

#### Manual:
```bash
# Dependencies
go mod download

# Build
go build -o honeylogger main.go

# Run
./honeylogger
```

## Usage

### Honeypot Access
```
Fake Admin Panel: http://localhost:8080/admin
Statistics: http://localhost:8080/stats (localhost only)
```

### Kibana Dashboard
```
1. Navigate to http://localhost:5601
2. Management → Saved Objects → Import
3. Upload kibana_dashboard.json file
4. Open the dashboard and monitor data
```

## Fake Endpoints

### Admin Panels
- `/admin`
- `/admin/login`
- `/administrator`
- `/wp-admin`
- `/cpanel`
- `/phpmyadmin`
- `/admin-panel`

### API Endpoints
- `/api/users`
- `/api/admin`
- `/api/login`
- `/api/config`
- `/api/database`

## Analysis Features

### Detected Attack Types
- **SQL Injection**: Union, Select, Drop, etc.
- **XSS**: Script tags, JavaScript execution
- **Path Traversal**: Directory climbing
- **Brute Force**: Multiple attempt detection
- **Credential Stuffing**: Common password detection

### Logged Information
```json
{
  "id": "uuid",
  "timestamp": "2025-11-05T17:00:00Z",
  "ip": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "method": "POST",
  "path": "/admin/login",
  "username": "admin",
  "password": "' OR '1'='1",
  "attack_type": "sql_injection",
  "threat_level": "critical",
  "is_bot": false,
  "attempt_count": 5,
  "country": "TR",
  "city": "Istanbul",
  "fingerprint": "a1b2c3d4..."
}
```

## Configuration

### Elasticsearch
```go
// In main.go
elasticLogger, err := logger.NewElasticLogger(
    []string{"http://localhost:9200"},
    "honeylogger-attacks",
)
```

### Change Port
```go
// In main.go
port := ":8080"  // Change to your desired port
```

## Kibana Visualizations

### Built-in Panels
1. **Total Attack Count**: Metric
2. **Attack Types**: Pie Chart
3. **Threat Levels**: Donut Chart
4. **Time Series**: Line Graph
5. **Top Attacking IPs**: Table
6. **Country Distribution**: Map
7. **Common Usernames**: Bar Chart
8. **Common Passwords**: Bar Chart
9. **Bot Detection**: Metric
10. **Real-time Feed**: Auto-refresh Table

## Security Notes

⚠️ **IMPORTANT**: This is a honeypot system!
- DO NOT use in real production systems
- Run only in isolated test environments
- Do not connect to real databases
- Never use real credentials

## Performance

- **Concurrency**: Goroutine-based async logging
- **Memory**: IP attempt cache (24h auto-cleanup)
- **Storage**: Elasticsearch optimized
- **Response**: Fake delay (500ms + attempt_count*100ms)

## Logging

### Elasticsearch Query Examples
```json
# Find all critical attacks
GET /honeylogger-attacks/_search
{
  "query": {
    "term": {"threat_level": "critical"}
  }
}

# List SQL Injection attempts
GET /honeylogger-attacks/_search
{
  "query": {
    "term": {"attack_type": "sql_injection"}
  }
}
```

## Learning Resources

### Detected Patterns
- SQL Injection: 14 different patterns
- XSS: 10 different patterns
- Bot Detection: 15+ user-agent patterns
- Common Passwords: 25 common passwords

## Support

Gmail: elalmisemre72@gmail.com

## License

MIT License - For educational and research purposes.

---

**HoneyLogger v1.0.0** - Trap attackers, keep your system secure!
