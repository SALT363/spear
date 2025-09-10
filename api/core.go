package api

// CoreAPI is the interface exposed to plugins for interacting with the core
type CoreAPI interface {
	// Trigger management
	RegisterTrigger(pluginID string, trigger TriggerDefinition) error
	ExecuteTrigger(triggerID string, args map[string]interface{}) error

	// Module management
	RegisterModule(pluginID string, module ModuleDefinition) error

	// Event handling
	EmitEvent(event Event) error
	SubscribeToEvents(filter EventFilter, handler EventHandler) error

	// Logging
	GetLogger(prefix string) Logger

	// Configuration
	ValidateConfig(pluginID string, config interface{}) error

	// File watching
	WatchFile(filePath string, module ModuleInstance, regex string) error
	WatchFileWithFallback(filePaths []string, module ModuleInstance, regex string) error
	UnwatchFile(filePath string, moduleID string) error
}
