package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config represents the main configuration structure
type Config struct {
	Core     CoreConfig              `toml:"core"`
	Plugins  map[string]PluginConfig `toml:"plugins"`
	Include  []IncludeConfig         `toml:"include"`
	Triggers []TriggerConfig         `toml:"trigger"`
	Raw      map[string]interface{}  `toml:",omitempty"`
}

// CoreConfig contains core daemon configuration
type CoreConfig struct {
	SocketPath string `toml:"socket_path"`
	PluginDir  string `toml:"plugin_dir"`
	LogLevel   string `toml:"log_level"`
	PIDFile    string `toml:"pid_file"`
}

// PluginConfig contains plugin-specific configuration
type PluginConfig struct {
	Enabled bool `toml:"enabled"`
}

// IncludeConfig specifies additional configuration files to include
type IncludeConfig struct {
	Files []string `toml:"files"`
}

// TriggerConfig defines a trigger instance
type TriggerConfig struct {
	ID     string                 `toml:"id"`
	Plugin string                 `toml:"plugin"`
	Action string                 `toml:"action"`
	Config map[string]interface{} `toml:",omitempty"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Core: CoreConfig{
			SocketPath: "/var/run/spear.sock",
			PluginDir:  "/usr/lib/spear/plugins",
			LogLevel:   "info",
			PIDFile:    "/var/run/spear.pid",
		},
		Plugins:  make(map[string]PluginConfig),
		Include:  []IncludeConfig{},
		Triggers: []TriggerConfig{},
		Raw:      make(map[string]interface{}),
	}
}

// LoadConfig loads configuration from the specified file
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	// Load main config file
	if err := loadConfigFile(configPath, config); err != nil {
		return nil, fmt.Errorf("failed to load main config: %w", err)
	}

	// Load included files
	baseDir := filepath.Dir(configPath)
	for _, include := range config.Include {
		for _, pattern := range include.Files {
			fullPattern := filepath.Join(baseDir, pattern)
			matches, err := filepath.Glob(fullPattern)
			if err != nil {
				return nil, fmt.Errorf("failed to glob pattern %s: %w", fullPattern, err)
			}

			for _, match := range matches {
				if match == configPath {
					continue // Skip the main config file
				}

				if err := loadConfigFile(match, config); err != nil {
					return nil, fmt.Errorf("failed to load included config %s: %w", match, err)
				}
			}
		}
	}

	return config, nil
}

// loadConfigFile loads a single configuration file and merges it into the existing config
func loadConfigFile(path string, config *Config) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", path)
	}

	var tempConfig Config
	if _, err := toml.DecodeFile(path, &tempConfig); err != nil {
		return fmt.Errorf("failed to decode config file %s: %w", path, err)
	}

	// Merge configurations
	mergeConfigs(config, &tempConfig)

	// Also decode into raw map for plugin-specific configurations
	var rawConfig map[string]interface{}
	if _, err := toml.DecodeFile(path, &rawConfig); err != nil {
		return fmt.Errorf("failed to decode raw config: %w", err)
	}

	for key, value := range rawConfig {
		if !isReservedConfigKey(key) {
			config.Raw[key] = value
		}
	}

	return nil
}

// mergeConfigs merges tempConfig into config
func mergeConfigs(config, tempConfig *Config) {
	// Merge core config (tempConfig takes precedence for non-empty values)
	if tempConfig.Core.SocketPath != "" {
		config.Core.SocketPath = tempConfig.Core.SocketPath
	}
	if tempConfig.Core.PluginDir != "" {
		config.Core.PluginDir = tempConfig.Core.PluginDir
	}
	if tempConfig.Core.LogLevel != "" {
		config.Core.LogLevel = tempConfig.Core.LogLevel
	}
	if tempConfig.Core.PIDFile != "" {
		config.Core.PIDFile = tempConfig.Core.PIDFile
	}

	// Merge plugins
	for k, v := range tempConfig.Plugins {
		config.Plugins[k] = v
	}

	// Append includes
	config.Include = append(config.Include, tempConfig.Include...)

	// Append triggers
	config.Triggers = append(config.Triggers, tempConfig.Triggers...)
}

// isReservedConfigKey checks if a config key is reserved for core use
func isReservedConfigKey(key string) bool {
	reserved := []string{"core", "plugins", "include", "trigger"}
	key = strings.ToLower(key)
	for _, r := range reserved {
		if key == r {
			return true
		}
	}
	return false
}

// GetPluginConfig extracts configuration for a specific plugin
func (c *Config) GetPluginConfig(pluginID string) (interface{}, bool) {
	if config, exists := c.Raw[pluginID]; exists {
		return config, true
	}
	return nil, false
}

// IsPluginEnabled checks if a plugin is enabled
func (c *Config) IsPluginEnabled(pluginID string) bool {
	if pluginConfig, exists := c.Plugins[pluginID]; exists {
		return pluginConfig.Enabled
	}
	return true // Default to enabled if not specified
}
