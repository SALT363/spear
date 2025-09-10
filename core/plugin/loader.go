package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"strings"

	"github.com/sammwyy/spear/api"
)

// Loader manages plugin loading and lifecycle
type Loader struct {
	pluginDir     string
	loadedPlugins map[string]*LoadedPlugin
	logger        api.Logger
	coreAPI       api.CoreAPI
}

// LoadedPlugin represents a loaded plugin
type LoadedPlugin struct {
	Plugin   api.Plugin
	FilePath string
	Enabled  bool
}

// NewLoader creates a new plugin loader
func NewLoader(pluginDir string, logger api.Logger, coreAPI api.CoreAPI) *Loader {
	return &Loader{
		pluginDir:     pluginDir,
		loadedPlugins: make(map[string]*LoadedPlugin),
		logger:        logger,
		coreAPI:       coreAPI,
	}
}

// LoadAll loads all plugins from the plugin directory
func (l *Loader) LoadAll() error {
	if _, err := os.Stat(l.pluginDir); os.IsNotExist(err) {
		l.logger.Warn("Plugin directory does not exist", "dir", l.pluginDir)
		return nil
	}

	entries, err := os.ReadDir(l.pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if strings.HasSuffix(entry.Name(), ".so") {
			pluginPath := filepath.Join(l.pluginDir, entry.Name())
			if err := l.LoadPlugin(pluginPath); err != nil {
				l.logger.Error("Failed to load plugin", "path", pluginPath, "error", err)
				continue
			}
		}
	}

	l.logger.Info("Loaded plugins", "count", len(l.loadedPlugins))
	return nil
}

// LoadPlugin loads a single plugin from the specified path
func (l *Loader) LoadPlugin(pluginPath string) error {
	l.logger.Debug("Loading plugin", "path", pluginPath)

	// Load the plugin
	p, err := plugin.Open(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	// Look for the NewPlugin symbol
	newPluginSym, err := p.Lookup("NewPlugin")
	if err != nil {
		return fmt.Errorf("plugin does not export NewPlugin function: %w", err)
	}

	// Cast to function
	newPluginFunc, ok := newPluginSym.(func() api.Plugin)
	if !ok {
		return fmt.Errorf("NewPlugin is not a valid function")
	}

	// Create plugin instance
	pluginInstance := newPluginFunc()

	// Get plugin metadata
	meta := pluginInstance.Meta()

	// Check if already loaded
	if _, exists := l.loadedPlugins[meta.ID]; exists {
		return fmt.Errorf("plugin %s is already loaded", meta.ID)
	}

	// Initialize plugin
	if err := pluginInstance.Initialize(l.coreAPI); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", meta.ID, err)
	}

	// Register modules and triggers
	modules := pluginInstance.RegisterModules()
	for _, module := range modules {
		if err := l.coreAPI.RegisterModule(meta.ID, module); err != nil {
			l.logger.Error("Failed to register module", "plugin", meta.ID, "module", module.Name, "error", err)
		}
	}

	triggers := pluginInstance.RegisterTriggers()
	for _, trigger := range triggers {
		if err := l.coreAPI.RegisterTrigger(meta.ID, trigger); err != nil {
			l.logger.Error("Failed to register trigger", "plugin", meta.ID, "trigger", trigger.Name, "error", err)
		}
	}

	// Store loaded plugin
	l.loadedPlugins[meta.ID] = &LoadedPlugin{
		Plugin:   pluginInstance,
		FilePath: pluginPath,
		Enabled:  true,
	}

	l.logger.Info("Loaded plugin", "id", meta.ID, "name", meta.DisplayName, "version", meta.Version)
	return nil
}

// GetPlugin returns a loaded plugin by ID
func (l *Loader) GetPlugin(id string) (*LoadedPlugin, bool) {
	plugin, exists := l.loadedPlugins[id]
	return plugin, exists
}

// GetAllPlugins returns all loaded plugins
func (l *Loader) GetAllPlugins() map[string]*LoadedPlugin {
	result := make(map[string]*LoadedPlugin)
	for k, v := range l.loadedPlugins {
		result[k] = v
	}
	return result
}

// UnloadPlugin unloads a plugin
func (l *Loader) UnloadPlugin(id string) error {
	loadedPlugin, exists := l.loadedPlugins[id]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", id)
	}

	// Shutdown plugin
	if err := loadedPlugin.Plugin.Shutdown(); err != nil {
		l.logger.Error("Failed to shutdown plugin", "id", id, "error", err)
	}

	// Remove from loaded plugins
	delete(l.loadedPlugins, id)

	l.logger.Info("Unloaded plugin", "id", id)
	return nil
}

// UnloadAll unloads all plugins
func (l *Loader) UnloadAll() {
	for id := range l.loadedPlugins {
		if err := l.UnloadPlugin(id); err != nil {
			l.logger.Error("Failed to unload plugin", "id", id, "error", err)
		}
	}
}

// ValidateConfig validates configuration for a plugin
func (l *Loader) ValidateConfig(pluginID string, config interface{}) error {
	loadedPlugin, exists := l.loadedPlugins[pluginID]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", pluginID)
	}

	return loadedPlugin.Plugin.ValidateConfig(config)
}
