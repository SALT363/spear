package core

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strconv"
	"syscall"

	"github.com/sammwyy/spear/api"
	"github.com/sammwyy/spear/core/config"
	"github.com/sammwyy/spear/core/eventbus"
	"github.com/sammwyy/spear/core/filewatcher"
	"github.com/sammwyy/spear/core/module"
	"github.com/sammwyy/spear/core/plugin"
	"github.com/sammwyy/spear/core/trigger"
)

// Daemon represents the main Spear daemon
type Daemon struct {
	config       *config.Config
	logger       api.Logger
	eventBus     *eventbus.EventBus
	fileWatcher  *filewatcher.FileWatcher
	pluginLoader *plugin.Loader
	moduleReg    *module.Registry
	triggerReg   *trigger.Registry
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewDaemon creates a new daemon instance
func NewDaemon(configPath string) (*Daemon, error) {
	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create logger
	logger := api.NewLogger("core")

	// Create context
	ctx, cancel := context.WithCancel(context.Background())

	// Create daemon
	daemon := &Daemon{
		config: cfg,
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize components
	daemon.eventBus = eventbus.NewEventBus(cfg.Core.SocketPath, api.NewLogger("eventbus"))
	daemon.fileWatcher, err = filewatcher.NewFileWatcher(api.NewLogger("filewatcher"), daemon)
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	daemon.moduleReg = module.NewRegistry(api.NewLogger("module"))
	daemon.triggerReg = trigger.NewRegistry(api.NewLogger("trigger"))
	daemon.pluginLoader = plugin.NewLoader(cfg.Core.PluginDir, api.NewLogger("plugin"), daemon)

	return daemon, nil
}

// Start starts the daemon
func (d *Daemon) Start() error {
	d.logger.Info("Starting Spear daemon")

	// Check and create PID file
	if err := d.createPIDFile(); err != nil {
		return fmt.Errorf("failed to create PID file: %w", err)
	}
	defer d.removePIDFile()

	// Start event bus
	if err := d.eventBus.Start(); err != nil {
		return fmt.Errorf("failed to start event bus: %w", err)
	}
	defer d.eventBus.Stop()

	// Start file watcher
	if err := d.fileWatcher.Start(); err != nil {
		return fmt.Errorf("failed to start file watcher: %w", err)
	}
	defer d.fileWatcher.Stop()

	// Load plugins
	if err := d.pluginLoader.LoadAll(); err != nil {
		return fmt.Errorf("failed to load plugins: %w", err)
	}
	defer d.pluginLoader.UnloadAll()

	// Process configuration and create instances
	if err := d.processConfiguration(); err != nil {
		return fmt.Errorf("failed to process configuration: %w", err)
	}

	// Start all modules
	if err := d.moduleReg.StartAll(); err != nil {
		d.logger.Error("Some modules failed to start", "error", err)
	}
	defer d.moduleReg.StopAll()

	d.logger.Info("Spear daemon started successfully")

	// Wait for shutdown signal
	d.waitForShutdown()

	d.logger.Info("Spear daemon shutting down")
	return nil
}

// processConfiguration processes the configuration and creates instances
func (d *Daemon) processConfiguration() error {
	// Process trigger configurations
	for _, triggerConfig := range d.config.Triggers {
		fullTriggerName := fmt.Sprintf("%s.%s", triggerConfig.Plugin, triggerConfig.Action)
		if err := d.triggerReg.CreateInstance(triggerConfig.ID, fullTriggerName, triggerConfig.Config); err != nil {
			d.logger.Error("Failed to create trigger instance", "id", triggerConfig.ID, "error", err)
			continue
		}
	}

	// Process plugin-specific configurations
	for pluginID, pluginConfig := range d.config.Raw {
		if !d.config.IsPluginEnabled(pluginID) {
			d.logger.Debug("Plugin disabled, skipping configuration", "plugin", pluginID)
			continue
		}

		// Check if this is a slice of configurations (multiple instances)
		configValue := reflect.ValueOf(pluginConfig)
		if configValue.Kind() == reflect.Slice {
			// Multiple instances
			for i := 0; i < configValue.Len(); i++ {
				instanceConfig := configValue.Index(i).Interface()
				instanceID := fmt.Sprintf("%s_%d", pluginID, i)

				// Extract ID if available
				if configMap, ok := instanceConfig.(map[string]interface{}); ok {
					if id, exists := configMap["id"]; exists {
						instanceID = fmt.Sprintf("%v", id)
					}
				}

				if err := d.createModuleInstance(pluginID, instanceID, instanceConfig); err != nil {
					d.logger.Error("Failed to create module instance", "plugin", pluginID, "instance", instanceID, "error", err)
				}
			}
		} else {
			// Single instance
			if err := d.createModuleInstance(pluginID, pluginID, pluginConfig); err != nil {
				d.logger.Error("Failed to create module instance", "plugin", pluginID, "error", err)
			}
		}
	}

	return nil
}

// createModuleInstance creates a module instance
func (d *Daemon) createModuleInstance(pluginID, instanceID string, config interface{}) error {
	// Find matching module definition
	definitions := d.moduleReg.GetAllDefinitions()
	var matchedDefinition string

	for defName := range definitions {
		if pluginID == defName || fmt.Sprintf("%s.", pluginID) == defName[:len(pluginID)+1] {
			matchedDefinition = defName
			break
		}
	}

	if matchedDefinition == "" {
		return fmt.Errorf("no module definition found for plugin %s", pluginID)
	}

	return d.moduleReg.CreateInstance(instanceID, matchedDefinition, config)
}

// createPIDFile creates a PID file
func (d *Daemon) createPIDFile() error {
	if d.config.Core.PIDFile == "" {
		return nil
	}

	// Check if PID file already exists
	if _, err := os.Stat(d.config.Core.PIDFile); err == nil {
		// Read existing PID
		data, err := os.ReadFile(d.config.Core.PIDFile)
		if err == nil {
			if pid, err := strconv.Atoi(string(data)); err == nil {
				// Check if process is running
				if process, err := os.FindProcess(pid); err == nil {
					if err := process.Signal(syscall.Signal(0)); err == nil {
						return fmt.Errorf("daemon is already running with PID %d", pid)
					}
				}
			}
		}
	}

	// Write current PID
	pid := os.Getpid()
	if err := os.WriteFile(d.config.Core.PIDFile, []byte(strconv.Itoa(pid)), 0644); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	d.logger.Debug("Created PID file", "path", d.config.Core.PIDFile, "pid", pid)
	return nil
}

// removePIDFile removes the PID file
func (d *Daemon) removePIDFile() {
	if d.config.Core.PIDFile != "" {
		if err := os.Remove(d.config.Core.PIDFile); err != nil && !os.IsNotExist(err) {
			d.logger.Error("Failed to remove PID file", "path", d.config.Core.PIDFile, "error", err)
		}
	}
}

// waitForShutdown waits for a shutdown signal
func (d *Daemon) waitForShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		d.logger.Info("Received shutdown signal", "signal", sig)
	case <-d.ctx.Done():
		d.logger.Info("Context cancelled")
	}

	d.cancel()
}

// CoreAPI implementation
func (d *Daemon) RegisterTrigger(pluginID string, trigger api.TriggerDefinition) error {
	return d.triggerReg.RegisterDefinition(pluginID, trigger)
}

func (d *Daemon) ExecuteTrigger(triggerID string, args map[string]interface{}) error {
	return d.triggerReg.ExecuteTrigger(triggerID, args)
}

func (d *Daemon) RegisterModule(pluginID string, module api.ModuleDefinition) error {
	return d.moduleReg.RegisterDefinition(pluginID, module)
}

func (d *Daemon) EmitEvent(event api.Event) error {
	return d.eventBus.EmitEvent(event)
}

func (d *Daemon) SubscribeToEvents(filter api.EventFilter, handler api.EventHandler) error {
	return d.eventBus.SubscribeToEvents(filter, handler)
}

func (d *Daemon) GetLogger(prefix string) api.Logger {
	return api.NewLogger(prefix)
}

func (d *Daemon) ValidateConfig(pluginID string, config interface{}) error {
	return d.pluginLoader.ValidateConfig(pluginID, config)
}

func (d *Daemon) WatchFile(filePath string, module api.ModuleInstance, regex string) error {
	return d.fileWatcher.RegisterModule(filePath, module, regex)
}

func (d *Daemon) WatchFileWithFallback(filePaths []string, module api.ModuleInstance, regex string) error {
	return d.fileWatcher.RegisterModuleWithFallback(filePaths, module, regex)
}

func (d *Daemon) UnwatchFile(filePath string, moduleID string) error {
	return d.fileWatcher.UnregisterModule(filePath, moduleID)
}
