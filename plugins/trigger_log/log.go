package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sammwyy/spear/api"
)

// LogPlugin is the main plugin struct
type LogPlugin struct {
	api    api.CoreAPI
	logger api.Logger
	mutex  sync.RWMutex
	files  map[string]*os.File // Cache of open file handles
}

// LogTriggerConfig represents the configuration for a log trigger
type LogTriggerConfig struct {
	File      string `toml:"file"`
	Format    string `toml:"format"`    // "json", "text", "csv"
	Timestamp bool   `toml:"timestamp"` // Include timestamp
	Append    bool   `toml:"append"`    // Append to file or overwrite
}

// LogTrigger represents an instance of the log trigger
type LogTrigger struct {
	id     string
	config LogTriggerConfig
	plugin *LogPlugin
	logger api.Logger
	file   *os.File
	mutex  sync.Mutex
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp,omitempty"`
	TriggerID string                 `json:"trigger_id"`
	Args      map[string]interface{} `json:"args"`
}

// NewPlugin creates a new log plugin instance
func NewPlugin() api.Plugin {
	return &LogPlugin{
		files: make(map[string]*os.File),
	}
}

// Meta returns plugin metadata
func (p *LogPlugin) Meta() api.PluginMeta {
	return api.PluginMeta{
		ID:          "log",
		DisplayName: "Log Trigger",
		Author:      "Spear Team",
		Repository:  "https://github.com/sammwyy/spear",
		Description: "Provides logging triggers to write events to files",
		Version:     "1.0.0",
	}
}

// Initialize initializes the plugin
func (p *LogPlugin) Initialize(apiInstance api.CoreAPI) error {
	p.api = apiInstance
	p.logger = apiInstance.GetLogger("log")
	p.logger.Info("Log plugin initialized")
	return nil
}

// Shutdown shuts down the plugin
func (p *LogPlugin) Shutdown() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Close all open file handles
	for path, file := range p.files {
		if err := file.Close(); err != nil {
			p.logger.Error("Failed to close log file", "path", path, "error", err)
		}
	}

	p.files = make(map[string]*os.File)
	p.logger.Info("Log plugin shut down")
	return nil
}

// ValidateConfig validates the plugin configuration
func (p *LogPlugin) ValidateConfig(config interface{}) error {
	logConfig, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid config type for log trigger")
	}

	// Check if file path is specified
	if _, exists := logConfig["file"]; !exists {
		return fmt.Errorf("log trigger config must specify 'file' parameter")
	}

	file := fmt.Sprintf("%v", logConfig["file"])
	if file == "" {
		return fmt.Errorf("log trigger 'file' parameter cannot be empty")
	}

	// Validate format if specified
	if formatVal, exists := logConfig["format"]; exists {
		format := fmt.Sprintf("%v", formatVal)
		switch format {
		case "json", "text", "csv", "":
			// Valid formats
		default:
			return fmt.Errorf("invalid log format '%s', supported formats: json, text, csv", format)
		}
	}

	// Validate file path can be created
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create log directory %s: %w", dir, err)
	}

	return nil
}

// GetConfigSchema returns the configuration schema
func (p *LogPlugin) GetConfigSchema() interface{} {
	return LogTriggerConfig{}
}

// RegisterModules returns the modules provided by this plugin
func (p *LogPlugin) RegisterModules() []api.ModuleDefinition {
	return []api.ModuleDefinition{} // This plugin doesn't provide modules
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *LogPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{
		{
			Name:        "log_file",
			Description: "Logs trigger arguments to a file",
			ConfigType:  nil, // Will be set dynamically
			Factory:     p.createLogTrigger,
		},
	}
}

// createLogTrigger creates a new log trigger instance
func (p *LogPlugin) createLogTrigger(config interface{}) (api.TriggerInstance, error) {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format for log trigger")
	}

	// Parse configuration
	var cfg LogTriggerConfig

	// Required: file path
	if file, exists := configMap["file"]; exists {
		cfg.File = fmt.Sprintf("%v", file)
	} else {
		return nil, fmt.Errorf("log trigger config must specify 'file' parameter")
	}

	// Optional: format (default: json)
	if format, exists := configMap["format"]; exists {
		cfg.Format = fmt.Sprintf("%v", format)
	} else {
		cfg.Format = "json"
	}

	// Optional: timestamp (default: true)
	if timestamp, exists := configMap["timestamp"]; exists {
		if ts, ok := timestamp.(bool); ok {
			cfg.Timestamp = ts
		} else {
			cfg.Timestamp = true
		}
	} else {
		cfg.Timestamp = true
	}

	// Optional: append (default: true)
	if append, exists := configMap["append"]; exists {
		if app, ok := append.(bool); ok {
			cfg.Append = app
		} else {
			cfg.Append = true
		}
	} else {
		cfg.Append = true
	}

	// Validate config
	if err := p.ValidateConfig(configMap); err != nil {
		return nil, err
	}

	// Create trigger instance
	trigger := &LogTrigger{
		id:     fmt.Sprintf("log_%d", time.Now().UnixNano()),
		config: cfg,
		plugin: p,
		logger: p.api.GetLogger(fmt.Sprintf("log.%s", filepath.Base(cfg.File))),
	}

	// Initialize the log file
	if err := trigger.initLogFile(); err != nil {
		return nil, fmt.Errorf("failed to initialize log file: %w", err)
	}

	p.logger.Debug("Created log trigger", "id", trigger.id, "file", cfg.File, "format", cfg.Format)
	return trigger, nil
}

// LogTrigger methods

func (t *LogTrigger) ID() string {
	return t.id
}

func (t *LogTrigger) Execute(args map[string]interface{}) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Create log entry
	entry := LogEntry{
		TriggerID: t.id,
		Args:      args,
	}

	if t.config.Timestamp {
		entry.Timestamp = time.Now()
	}

	// Format and write the log entry
	var output string
	var err error

	switch t.config.Format {
	case "json":
		output, err = t.formatJSON(entry)
	case "text":
		output, err = t.formatText(entry)
	case "csv":
		output, err = t.formatCSV(entry)
	default:
		output, err = t.formatJSON(entry)
	}

	if err != nil {
		return fmt.Errorf("failed to format log entry: %w", err)
	}

	// Write to file
	if _, err := t.file.WriteString(output + "\n"); err != nil {
		return fmt.Errorf("failed to write to log file: %w", err)
	}

	// Sync to ensure data is written
	if err := t.file.Sync(); err != nil {
		t.logger.Error("Failed to sync log file", "error", err)
	}

	t.logger.Debug("Logged trigger execution", "args_count", len(args))
	return nil
}

func (t *LogTrigger) GetArgumentSchema() map[string]api.ArgumentSpec {
	return map[string]api.ArgumentSpec{
		"*": {
			Type:        "any",
			Required:    false,
			Description: "Any arguments will be logged to the file",
		},
	}
}

// initLogFile initializes the log file
func (t *LogTrigger) initLogFile() error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(t.config.File)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Determine file opening flags
	flags := os.O_WRONLY | os.O_CREATE
	if t.config.Append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	// Open the file
	file, err := os.OpenFile(t.config.File, flags, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", t.config.File, err)
	}

	t.file = file

	// Write header for CSV format if file is new or truncated
	if t.config.Format == "csv" && (!t.config.Append || t.isNewFile()) {
		header := "timestamp,trigger_id,event_type,service,user,ip,raw_line\n"
		if _, err := t.file.WriteString(header); err != nil {
			return fmt.Errorf("failed to write CSV header: %w", err)
		}
	}

	t.logger.Info("Initialized log file", "path", t.config.File, "format", t.config.Format, "append", t.config.Append)
	return nil
}

// isNewFile checks if the log file is new/empty
func (t *LogTrigger) isNewFile() bool {
	info, err := t.file.Stat()
	if err != nil {
		return true
	}
	return info.Size() == 0
}

// formatJSON formats the log entry as JSON
func (t *LogTrigger) formatJSON(entry LogEntry) (string, error) {
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// formatText formats the log entry as human-readable text
func (t *LogTrigger) formatText(entry LogEntry) (string, error) {
	var output string

	if t.config.Timestamp && !entry.Timestamp.IsZero() {
		output += fmt.Sprintf("[%s] ", entry.Timestamp.Format("2006-01-02 15:04:05"))
	}

	output += fmt.Sprintf("Trigger: %s", entry.TriggerID)

	if len(entry.Args) > 0 {
		output += " | Args: "
		var args []string
		for key, value := range entry.Args {
			args = append(args, fmt.Sprintf("%s=%v", key, value))
		}
		output += fmt.Sprintf("{%s}", fmt.Sprintf("%v", args))
	}

	return output, nil
}

// formatCSV formats the log entry as CSV
func (t *LogTrigger) formatCSV(entry LogEntry) (string, error) {
	timestamp := ""
	if t.config.Timestamp && !entry.Timestamp.IsZero() {
		timestamp = entry.Timestamp.Format("2006-01-02 15:04:05")
	}

	// Extract common fields
	eventType := t.getStringArg(entry.Args, "event_type")
	service := t.getStringArg(entry.Args, "service")
	user := t.getStringArg(entry.Args, "user")
	ip := t.getStringArg(entry.Args, "ip")
	rawLine := t.getStringArg(entry.Args, "raw_line")

	// Escape CSV fields
	timestamp = t.escapeCSV(timestamp)
	triggerID := t.escapeCSV(entry.TriggerID)
	eventType = t.escapeCSV(eventType)
	service = t.escapeCSV(service)
	user = t.escapeCSV(user)
	ip = t.escapeCSV(ip)
	rawLine = t.escapeCSV(rawLine)

	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s",
		timestamp, triggerID, eventType, service, user, ip, rawLine), nil
}

// getStringArg safely extracts a string argument
func (t *LogTrigger) getStringArg(args map[string]interface{}, key string) string {
	if value, exists := args[key]; exists {
		return fmt.Sprintf("%v", value)
	}
	return ""
}

// escapeCSV escapes a string for CSV format
func (t *LogTrigger) escapeCSV(value string) string {
	if value == "" {
		return ""
	}

	// If the value contains comma, quote, or newline, wrap in quotes and escape quotes
	if containsSpecialChars(value) {
		value = `"` + escapeQuotes(value) + `"`
	}

	return value
}

// containsSpecialChars checks if a string contains CSV special characters
func containsSpecialChars(s string) bool {
	for _, char := range s {
		if char == ',' || char == '"' || char == '\n' || char == '\r' {
			return true
		}
	}
	return false
}

// escapeQuotes escapes quotes in a string
func escapeQuotes(s string) string {
	result := ""
	for _, char := range s {
		if char == '"' {
			result += `""`
		} else {
			result += string(char)
		}
	}
	return result
}
