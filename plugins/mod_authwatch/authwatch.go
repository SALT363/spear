package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/sammwyy/spear/api"
)

// AuthWatchPlugin is the main plugin struct
type AuthWatchPlugin struct {
	api    api.CoreAPI
	logger api.Logger
}

// AuthWatchConfig represents the configuration for an authwatch instance
type AuthWatchConfig struct {
	ID              string   `toml:"id"`
	Services        []string `toml:"services"`
	Triggers        []string `toml:"triggers"`
	TimeWindow      int      `toml:"time_window"`      // Time window in seconds (default: 300)
	MaxHits         int      `toml:"max_hits"`         // Max hits before triggering (default: 5)
	CleanupInterval int      `toml:"cleanup_interval"` // Cleanup interval in seconds (default: 600)
	TrackSuccessful bool     `toml:"track_successful"` // Track successful logins (default: false)
	TrackFailed     bool     `toml:"track_failed"`     // Track failed logins (default: true)
}

// AuthWatchModule represents an instance of the authwatch module
type AuthWatchModule struct {
	id       string
	config   AuthWatchConfig
	api      api.CoreAPI
	logger   api.Logger
	services map[string]*ServiceDefinition
	tracker  *api.TimeWindowTracker[*AuthData]
}

// AuthData represents authentication data for tracking
type AuthData struct {
	IP            string
	User          string
	Service       string
	SuccessCount  int
	FailureCount  int
	LastEventType string
	LastRawLine   string
}

// ServiceDefinition defines how to parse authentication events for a service
type ServiceDefinition struct {
	ID             string
	Name           string
	LogFiles       []string
	SuccessRegex   *regexp.Regexp
	SuccessIPRegex *regexp.Regexp
	FailureRegex   *regexp.Regexp
	FailureIPRegex *regexp.Regexp
	UserRegex      *regexp.Regexp
	CombinedRegex  *regexp.Regexp
}

// AuthEvent represents a parsed authentication event
type AuthEvent struct {
	Type      string // "success" or "failure"
	Service   string
	User      string
	IP        string
	Timestamp time.Time
	RawLine   string
}

// NewPlugin creates a new authwatch plugin instance
func NewPlugin() api.Plugin {
	return &AuthWatchPlugin{}
}

// Meta returns plugin metadata
func (p *AuthWatchPlugin) Meta() api.PluginMeta {
	return api.PluginMeta{
		ID:          "authwatch",
		DisplayName: "Authentication Watcher",
		Author:      "Spear Team",
		Repository:  "https://github.com/sammwyy/spear",
		Description: "Monitors authentication logs for successful and failed login attempts with time window tracking",
		Version:     "1.0.0",
	}
}

// Initialize initializes the plugin
func (p *AuthWatchPlugin) Initialize(apiInstance api.CoreAPI) error {
	p.api = apiInstance
	p.logger = apiInstance.GetLogger("authwatch")
	p.logger.Info("AuthWatch plugin initialized")
	return nil
}

// Shutdown shuts down the plugin
func (p *AuthWatchPlugin) Shutdown() error {
	p.logger.Info("AuthWatch plugin shutting down")
	return nil
}

// ValidateConfig validates the plugin configuration
func (p *AuthWatchPlugin) ValidateConfig(config interface{}) error {
	authConfig, ok := config.(AuthWatchConfig)
	if !ok {
		return fmt.Errorf("invalid config type for authwatch")
	}

	if authConfig.ID == "" {
		return fmt.Errorf("authwatch config must have an ID")
	}

	if len(authConfig.Services) == 0 {
		return fmt.Errorf("authwatch config must specify at least one service")
	}

	// Validate time window
	if authConfig.TimeWindow < 0 {
		return fmt.Errorf("time_window must be positive")
	}

	// Validate max hits
	if authConfig.MaxHits <= 0 {
		return fmt.Errorf("max_hits must be positive")
	}

	// Validate that all services are supported
	supportedServices := p.getSupportedServices()
	for _, service := range authConfig.Services {
		if _, exists := supportedServices[service]; !exists {
			return fmt.Errorf("unsupported service: %s", service)
		}
	}

	return nil
}

// GetConfigSchema returns the configuration schema
func (p *AuthWatchPlugin) GetConfigSchema() interface{} {
	return AuthWatchConfig{}
}

// RegisterModules returns the modules provided by this plugin
func (p *AuthWatchPlugin) RegisterModules() []api.ModuleDefinition {
	return []api.ModuleDefinition{
		{
			Name:        "authwatch",
			Description: "Authentication monitoring module with time window tracking",
			ConfigType:  nil,
			Factory:     p.createAuthWatchModule,
		},
	}
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *AuthWatchPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{}
}

// createAuthWatchModule creates a new authwatch module instance
func (p *AuthWatchPlugin) createAuthWatchModule(config interface{}) (api.ModuleInstance, error) {
	authConfig, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format")
	}

	// Parse config with defaults
	var cfg AuthWatchConfig
	cfg.TimeWindow = 300      // 5 minutes default
	cfg.MaxHits = 5           // 5 hits default
	cfg.CleanupInterval = 600 // 10 minutes default
	cfg.TrackSuccessful = false
	cfg.TrackFailed = true

	if err := p.parseConfig(authConfig, &cfg); err != nil {
		return nil, err
	}

	// Validate config
	if err := p.ValidateConfig(cfg); err != nil {
		return nil, err
	}

	module := &AuthWatchModule{
		id:       cfg.ID,
		config:   cfg,
		api:      p.api,
		logger:   p.api.GetLogger(fmt.Sprintf("authwatch.%s", cfg.ID)),
		services: make(map[string]*ServiceDefinition),
	}

	// Initialize service definitions
	supportedServices := p.getSupportedServices()
	for _, serviceName := range cfg.Services {
		if serviceDef, exists := supportedServices[serviceName]; exists {
			module.services[serviceName] = serviceDef
		}
	}

	// Initialize time window tracker
	trackerConfig := api.TimeWindowConfig{
		TimeWindow:      time.Duration(cfg.TimeWindow) * time.Second,
		MaxHits:         cfg.MaxHits,
		CleanupInterval: time.Duration(cfg.CleanupInterval) * time.Second,
	}

	module.tracker = api.NewTimeWindowTracker[*AuthData](
		trackerConfig,
		module.onThresholdReached,
		module.logger,
	)

	return module, nil
}

// parseConfig parses configuration from map to struct
func (p *AuthWatchPlugin) parseConfig(configMap map[string]interface{}, cfg *AuthWatchConfig) error {
	if id, exists := configMap["id"]; exists {
		cfg.ID = fmt.Sprintf("%v", id)
	}

	if services, exists := configMap["services"]; exists {
		if serviceSlice, ok := services.([]interface{}); ok {
			for _, svc := range serviceSlice {
				cfg.Services = append(cfg.Services, fmt.Sprintf("%v", svc))
			}
		}
	}

	if triggers, exists := configMap["triggers"]; exists {
		if triggerSlice, ok := triggers.([]interface{}); ok {
			for _, trigger := range triggerSlice {
				cfg.Triggers = append(cfg.Triggers, fmt.Sprintf("%v", trigger))
			}
		}
	}

	if timeWindow, exists := configMap["time_window"]; exists {
		if tw, ok := timeWindow.(int64); ok {
			cfg.TimeWindow = int(tw)
		}
	}

	if maxHits, exists := configMap["max_hits"]; exists {
		if mh, ok := maxHits.(int64); ok {
			cfg.MaxHits = int(mh)
		}
	}

	if cleanupInterval, exists := configMap["cleanup_interval"]; exists {
		if ci, ok := cleanupInterval.(int64); ok {
			cfg.CleanupInterval = int(ci)
		}
	}

	if trackSuccessful, exists := configMap["track_successful"]; exists {
		if ts, ok := trackSuccessful.(bool); ok {
			cfg.TrackSuccessful = ts
		}
	}

	if trackFailed, exists := configMap["track_failed"]; exists {
		if tf, ok := trackFailed.(bool); ok {
			cfg.TrackFailed = tf
		}
	}

	return nil
}

// getSupportedServices returns all supported authentication services
func (p *AuthWatchPlugin) getSupportedServices() map[string]*ServiceDefinition {
	services := make(map[string]*ServiceDefinition)

	// SSH Service
	services["ssh"] = &ServiceDefinition{
		ID:   "ssh",
		Name: "SSH",
		LogFiles: []string{
			"/var/log/auth.log",
			"/var/log/secure",
			"/var/log/messages",
		},
		SuccessRegex:   regexp.MustCompile(`Accepted\s+(?:password|publickey|keyboard-interactive)\s+for\s+(\w+)\s+from\s+([\d.]+)`),
		SuccessIPRegex: regexp.MustCompile(`from\s+([\d.]+)`),
		FailureRegex:   regexp.MustCompile(`Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\w+)\s+from\s+([\d.]+)`),
		FailureIPRegex: regexp.MustCompile(`from\s+([\d.]+)`),
		UserRegex:      regexp.MustCompile(`(?:for|user)\s+(\w+)`),
	}

	// sudo Service
	services["sudo"] = &ServiceDefinition{
		ID:   "sudo",
		Name: "Sudo",
		LogFiles: []string{
			"/var/log/auth.log",
			"/var/log/secure",
			"/var/log/messages",
		},
		SuccessRegex: regexp.MustCompile(`(\w+)\s*:\s*TTY=.*\s*;\s*PWD=.*\s*;\s*USER=.*\s*;\s*COMMAND=`),
		FailureRegex: regexp.MustCompile(`(\w+)\s*:\s*(?:command not allowed|authentication failure|incorrect password)`),
		UserRegex:    regexp.MustCompile(`^(\w+)\s*:`),
	}

	// FTP Service
	services["ftp"] = &ServiceDefinition{
		ID:   "ftp",
		Name: "FTP",
		LogFiles: []string{
			"/var/log/vsftpd.log",
			"/var/log/ftp.log",
			"/var/log/messages",
		},
		SuccessRegex:   regexp.MustCompile(`OK LOGIN:\s*Client\s*"([\d.]+)",\s*anon\s*password\s*"([^"]*)".*user\s*"([^"]*)"?`),
		FailureRegex:   regexp.MustCompile(`FAIL LOGIN:\s*Client\s*"([\d.]+)".*user\s*"([^"]*)"?`),
		SuccessIPRegex: regexp.MustCompile(`Client\s*"([\d.]+)"`),
		FailureIPRegex: regexp.MustCompile(`Client\s*"([\d.]+)"`),
		UserRegex:      regexp.MustCompile(`user\s*"([^"]*)"`),
	}

	// Apache/Web Authentication
	services["web"] = &ServiceDefinition{
		ID:   "web",
		Name: "Web Authentication",
		LogFiles: []string{
			"/var/log/apache2/access.log",
			"/var/log/httpd/access_log",
			"/var/log/nginx/access.log",
		},
		FailureRegex:   regexp.MustCompile(`([\d.]+).*"(?:GET|POST).*(?:401|403|404)`),
		FailureIPRegex: regexp.MustCompile(`^([\d.]+)`),
	}

	return services
}

// AuthWatchModule methods

func (m *AuthWatchModule) ID() string {
	return m.id
}

func (m *AuthWatchModule) Start() error {
	m.logger.Info("Starting AuthWatch module",
		"services", m.config.Services,
		"time_window", m.config.TimeWindow,
		"max_hits", m.config.MaxHits)

	// Start time window tracker
	m.tracker.Start()

	// Register file watchers for each service
	for serviceName, serviceDef := range m.services {
		regexPattern := m.buildCombinedRegex(serviceDef)

		if err := m.api.WatchFileWithFallback(serviceDef.LogFiles, m, regexPattern); err != nil {
			m.logger.Error("Failed to register file watcher for service", "service", serviceName, "error", err)
			continue
		}

		m.logger.Info("Registered file watcher for service", "service", serviceName, "files", serviceDef.LogFiles)
	}

	return nil
}

func (m *AuthWatchModule) Stop() error {
	m.logger.Info("Stopping AuthWatch module")

	if m.tracker != nil {
		m.tracker.Stop()
	}

	return nil
}

func (m *AuthWatchModule) HandleEvent(event api.Event) error {
	if event.Type != "file_line" {
		return nil
	}

	line, ok := event.Payload["line"].(string)
	if !ok {
		return nil
	}

	// Parse the authentication event
	authEvent := m.parseAuthEvent(line)
	if authEvent == nil {
		return nil
	}

	// Check if we should track this event type
	if authEvent.Type == "success" && !m.config.TrackSuccessful {
		return nil
	}
	if authEvent.Type == "failure" && !m.config.TrackFailed {
		return nil
	}

	m.logger.Debug("Authentication event detected",
		"type", authEvent.Type,
		"service", authEvent.Service,
		"user", authEvent.User,
		"ip", authEvent.IP)

	// Track the authentication event
	return m.trackAuthEvent(authEvent)
}

// trackAuthEvent tracks an authentication event using the time window tracker
func (m *AuthWatchModule) trackAuthEvent(authEvent *AuthEvent) error {
	// Create tracking key (IP-based tracking)
	trackingKey := authEvent.IP

	// Get existing data or create new
	var authData *AuthData
	if entry, exists := m.tracker.Get(trackingKey); exists {
		authData = entry.Data
	} else {
		authData = &AuthData{
			IP:      authEvent.IP,
			Service: authEvent.Service,
		}
	}

	// Update auth data
	authData.User = authEvent.User
	authData.Service = authEvent.Service
	authData.LastEventType = authEvent.Type
	authData.LastRawLine = authEvent.RawLine

	if authEvent.Type == "success" {
		authData.SuccessCount++
	} else {
		authData.FailureCount++
	}

	// Create metadata for the tracker
	metadata := map[string]interface{}{
		"user":          authEvent.User,
		"service":       authEvent.Service,
		"event_type":    authEvent.Type,
		"timestamp":     authEvent.Timestamp,
		"raw_line":      authEvent.RawLine,
		"success_count": authData.SuccessCount,
		"failure_count": authData.FailureCount,
	}

	// Track the event
	m.tracker.Track(trackingKey, authData, metadata)

	return nil
}

// onThresholdReached is called when the threshold is reached
func (m *AuthWatchModule) onThresholdReached(key string, entry *api.TimeWindowEntry[*AuthData]) {
	authData := entry.Data

	m.logger.Warn("Authentication threshold reached",
		"ip", authData.IP,
		"user", authData.User,
		"service", authData.Service,
		"hits", entry.HitCount,
		"max_hits", m.config.MaxHits,
		"time_window", m.config.TimeWindow,
		"success_count", authData.SuccessCount,
		"failure_count", authData.FailureCount)

	// Prepare trigger arguments
	args := map[string]interface{}{
		"alert_type":      "auth_threshold",
		"ip":              authData.IP,
		"user":            authData.User,
		"service":         authData.Service,
		"hits":            entry.HitCount,
		"max_hits":        m.config.MaxHits,
		"time_window":     m.config.TimeWindow,
		"success_count":   authData.SuccessCount,
		"failure_count":   authData.FailureCount,
		"first_seen":      entry.FirstSeen,
		"last_seen":       entry.LastSeen,
		"last_event_type": authData.LastEventType,
		"raw_line":        authData.LastRawLine,
		"metadata":        entry.Metadata,
		"severity":        m.calculateSeverity(authData),
	}

	// Execute configured triggers
	for _, triggerID := range m.config.Triggers {
		if err := m.api.ExecuteTrigger(triggerID, args); err != nil {
			m.logger.Error("Failed to execute trigger", "trigger", triggerID, "error", err)
		}
	}
}

// calculateSeverity calculates severity based on authentication data
func (m *AuthWatchModule) calculateSeverity(authData *AuthData) string {
	// High severity for many failures with few successes
	if authData.FailureCount > 10 && authData.SuccessCount == 0 {
		return "high"
	}

	// Medium severity for mixed success/failure
	if authData.FailureCount > 5 {
		return "medium"
	}

	// Low severity for mostly successes
	return "low"
}

// buildCombinedRegex builds a combined regex that matches any authentication event for a service
func (m *AuthWatchModule) buildCombinedRegex(serviceDef *ServiceDefinition) string {
	var patterns []string

	if serviceDef.SuccessRegex != nil && m.config.TrackSuccessful {
		patterns = append(patterns, serviceDef.SuccessRegex.String())
	}

	if serviceDef.FailureRegex != nil && m.config.TrackFailed {
		patterns = append(patterns, serviceDef.FailureRegex.String())
	}

	if len(patterns) == 0 {
		return ".*" // Match everything if no patterns defined
	}

	return "(" + strings.Join(patterns, "|") + ")"
}

// parseAuthEvent parses an authentication event from a log line
func (m *AuthWatchModule) parseAuthEvent(line string) *AuthEvent {
	for serviceName, serviceDef := range m.services {
		// Check for success
		if serviceDef.SuccessRegex != nil && serviceDef.SuccessRegex.MatchString(line) {
			return &AuthEvent{
				Type:      "success",
				Service:   serviceName,
				User:      m.extractUser(line, serviceDef),
				IP:        m.extractIP(line, serviceDef, true),
				Timestamp: time.Now(),
				RawLine:   line,
			}
		}

		// Check for failure
		if serviceDef.FailureRegex != nil && serviceDef.FailureRegex.MatchString(line) {
			return &AuthEvent{
				Type:      "failure",
				Service:   serviceName,
				User:      m.extractUser(line, serviceDef),
				IP:        m.extractIP(line, serviceDef, false),
				Timestamp: time.Now(),
				RawLine:   line,
			}
		}
	}

	return nil
}

// extractUser extracts username from log line
func (m *AuthWatchModule) extractUser(line string, serviceDef *ServiceDefinition) string {
	if serviceDef.UserRegex == nil {
		return ""
	}

	matches := serviceDef.UserRegex.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// extractIP extracts IP address from log line
func (m *AuthWatchModule) extractIP(line string, serviceDef *ServiceDefinition, success bool) string {
	var ipRegex *regexp.Regexp

	if success && serviceDef.SuccessIPRegex != nil {
		ipRegex = serviceDef.SuccessIPRegex
	} else if !success && serviceDef.FailureIPRegex != nil {
		ipRegex = serviceDef.FailureIPRegex
	}

	if ipRegex == nil {
		return ""
	}

	matches := ipRegex.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}
