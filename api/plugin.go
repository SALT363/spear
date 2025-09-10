package api

// Plugin is the main interface that all plugins must implement
type Plugin interface {
	// Meta returns plugin metadata
	Meta() PluginMeta

	// Initialize is called when the plugin is loaded
	Initialize(api CoreAPI) error

	// Shutdown is called when the plugin is unloaded
	Shutdown() error

	// ValidateConfig validates plugin configuration
	ValidateConfig(config interface{}) error

	// GetConfigSchema returns the configuration schema
	GetConfigSchema() interface{}

	// RegisterModules returns modules provided by this plugin
	RegisterModules() []ModuleDefinition

	// RegisterTriggers returns triggers provided by this plugin
	RegisterTriggers() []TriggerDefinition
}
