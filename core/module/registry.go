package module

import (
	"fmt"
	"sync"

	"github.com/sammwyy/spear/api"
)

// Registry manages module definitions and instances
type Registry struct {
	definitions map[string]api.ModuleDefinition
	instances   map[string]api.ModuleInstance
	mutex       sync.RWMutex
	logger      api.Logger
}

// NewRegistry creates a new module registry
func NewRegistry(logger api.Logger) *Registry {
	return &Registry{
		definitions: make(map[string]api.ModuleDefinition),
		instances:   make(map[string]api.ModuleInstance),
		logger:      logger,
	}
}

// RegisterDefinition registers a module definition
func (r *Registry) RegisterDefinition(pluginID string, definition api.ModuleDefinition) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	fullName := fmt.Sprintf("%s.%s", pluginID, definition.Name)

	if _, exists := r.definitions[fullName]; exists {
		return fmt.Errorf("module definition %s already exists", fullName)
	}

	r.definitions[fullName] = definition
	r.logger.Debug("Registered module definition", "name", fullName, "plugin", pluginID)
	return nil
}

// CreateInstance creates a new module instance
func (r *Registry) CreateInstance(moduleID, definitionName string, config interface{}) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	definition, exists := r.definitions[definitionName]
	if !exists {
		return fmt.Errorf("module definition %s not found", definitionName)
	}

	if _, exists := r.instances[moduleID]; exists {
		return fmt.Errorf("module instance %s already exists", moduleID)
	}

	instance, err := definition.Factory(config)
	if err != nil {
		return fmt.Errorf("failed to create module instance: %w", err)
	}

	r.instances[moduleID] = instance
	r.logger.Debug("Created module instance", "id", moduleID, "definition", definitionName)
	return nil
}

// GetInstance returns a module instance by ID
func (r *Registry) GetInstance(moduleID string) (api.ModuleInstance, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	instance, exists := r.instances[moduleID]
	return instance, exists
}

// GetDefinition returns a module definition by name
func (r *Registry) GetDefinition(name string) (api.ModuleDefinition, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	definition, exists := r.definitions[name]
	return definition, exists
}

// GetAllDefinitions returns all module definitions
func (r *Registry) GetAllDefinitions() map[string]api.ModuleDefinition {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make(map[string]api.ModuleDefinition)
	for k, v := range r.definitions {
		result[k] = v
	}
	return result
}

// GetAllInstances returns all module instances
func (r *Registry) GetAllInstances() map[string]api.ModuleInstance {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make(map[string]api.ModuleInstance)
	for k, v := range r.instances {
		result[k] = v
	}
	return result
}

// StartInstance starts a module instance
func (r *Registry) StartInstance(moduleID string) error {
	r.mutex.RLock()
	instance, exists := r.instances[moduleID]
	r.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("module instance %s not found", moduleID)
	}

	return instance.Start()
}

// StopInstance stops a module instance
func (r *Registry) StopInstance(moduleID string) error {
	r.mutex.RLock()
	instance, exists := r.instances[moduleID]
	r.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("module instance %s not found", moduleID)
	}

	return instance.Stop()
}

// RemoveInstance removes a module instance
func (r *Registry) RemoveInstance(moduleID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	instance, exists := r.instances[moduleID]
	if !exists {
		return fmt.Errorf("module instance %s not found", moduleID)
	}

	// Stop the instance first
	if err := instance.Stop(); err != nil {
		r.logger.Error("Failed to stop module instance", "id", moduleID, "error", err)
	}

	delete(r.instances, moduleID)
	r.logger.Debug("Removed module instance", "id", moduleID)
	return nil
}

// StartAll starts all module instances
func (r *Registry) StartAll() error {
	r.mutex.RLock()
	instances := make(map[string]api.ModuleInstance)
	for k, v := range r.instances {
		instances[k] = v
	}
	r.mutex.RUnlock()

	var firstError error
	for id, instance := range instances {
		if err := instance.Start(); err != nil {
			r.logger.Error("Failed to start module instance", "id", id, "error", err)
			if firstError == nil {
				firstError = err
			}
		} else {
			r.logger.Debug("Started module instance", "id", id)
		}
	}

	return firstError
}

// StopAll stops all module instances
func (r *Registry) StopAll() error {
	r.mutex.RLock()
	instances := make(map[string]api.ModuleInstance)
	for k, v := range r.instances {
		instances[k] = v
	}
	r.mutex.RUnlock()

	var firstError error
	for id, instance := range instances {
		if err := instance.Stop(); err != nil {
			r.logger.Error("Failed to stop module instance", "id", id, "error", err)
			if firstError == nil {
				firstError = err
			}
		} else {
			r.logger.Debug("Stopped module instance", "id", id)
		}
	}

	return firstError
}
