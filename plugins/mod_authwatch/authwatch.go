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
	ID       string   `toml:"id"`
	Services []string `toml:"services"`
	Triggers []string `toml:"triggers"`
}

// AuthWatchModule represents an instance of the authwatch module
type AuthWatchModule struct {
	id       string
	config   AuthWatchConfig
	api      api.CoreAPI
	logger   api.Logger
	services map[string]*ServiceDefinition
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
	CombinedRegex  *regexp.Regexp // For services that have success/failure in one pattern
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
		Description: "Monitors authentication logs for successful and failed login attempts",
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
			Description: "Authentication monitoring module",
			ConfigType:  nil, // Will be set dynamically
			Factory:     p.createAuthWatchModule,
		},
	}
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *AuthWatchPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{} // This plugin doesn't provide triggers
}

// createAuthWatchModule creates a new authwatch module instance
func (p *AuthWatchPlugin) createAuthWatchModule(config interface{}) (api.ModuleInstance, error) {
	authConfig, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format")
	}

	// Parse config
	var cfg AuthWatchConfig

	if id, exists := authConfig["id"]; exists {
		cfg.ID = fmt.Sprintf("%v", id)
	}

	if services, exists := authConfig["services"]; exists {
		if serviceSlice, ok := services.([]interface{}); ok {
			for _, svc := range serviceSlice {
				cfg.Services = append(cfg.Services, fmt.Sprintf("%v", svc))
			}
		}
	}

	if triggers, exists := authConfig["triggers"]; exists {
		if triggerSlice, ok := triggers.([]interface{}); ok {
			for _, trigger := range triggerSlice {
				cfg.Triggers = append(cfg.Triggers, fmt.Sprintf("%v", trigger))
			}
		}
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

	return module, nil
}

// getSupportedServices returns all supported authentication services
func (p *AuthWatchPlugin) getSupportedServices() map[string]*ServiceDefinition {
	services := make(map[string]*ServiceDefinition)

	// SSH Service
	services["ssh"] = &ServiceDefinition{
		ID:   "ssh",
		Name: "SSH",
		LogFiles: []string{
			"/var/log/auth.log", // Ubuntu/Debian
			"/var/log/secure",   // RHEL/CentOS/Fedora
			"/var/log/messages", // Some distributions
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
	m.logger.Info("Starting AuthWatch module", "services", m.config.Services)

	// Register file watchers for each service
	for serviceName, serviceDef := range m.services {
		// Create a combined regex that matches any authentication event
		regexPattern := m.buildCombinedRegex(serviceDef)

		// Register with fallback file paths
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
		return nil // No authentication event found
	}

	m.logger.Debug("Authentication event detected",
		"type", authEvent.Type,
		"service", authEvent.Service,
		"user", authEvent.User,
		"ip", authEvent.IP)

	// Execute configured triggers
	return m.executeTriggers(authEvent)
}

// buildCombinedRegex builds a combined regex that matches any authentication event for a service
func (m *AuthWatchModule) buildCombinedRegex(serviceDef *ServiceDefinition) string {
	var patterns []string

	if serviceDef.SuccessRegex != nil {
		patterns = append(patterns, serviceDef.SuccessRegex.String())
	}

	if serviceDef.FailureRegex != nil {
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

// executeTriggers executes all configured triggers with the authentication event data
func (m *AuthWatchModule) executeTriggers(authEvent *AuthEvent) error {
	if len(m.config.Triggers) == 0 {
		return nil
	}

	// Prepare trigger arguments
	args := map[string]interface{}{
		"event_type": authEvent.Type,
		"service":    authEvent.Service,
		"user":       authEvent.User,
		"ip":         authEvent.IP,
		"timestamp":  authEvent.Timestamp,
		"raw_line":   authEvent.RawLine,
	}

	// Execute each configured trigger
	for _, triggerID := range m.config.Triggers {
		if err := m.api.ExecuteTrigger(triggerID, args); err != nil {
			m.logger.Error("Failed to execute trigger", "trigger", triggerID, "error", err)
		} else {
			m.logger.Debug("Executed trigger", "trigger", triggerID, "event", authEvent.Type)
		}
	}

	return nil
}
