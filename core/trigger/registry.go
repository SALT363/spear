package trigger

import (
	"fmt"
	"sync"

	"github.com/sammwyy/spear/api"
)

// Registry manages trigger definitions and instances
type Registry struct {
	definitions map[string]api.TriggerDefinition
	instances   map[string]api.TriggerInstance
	mutex       sync.RWMutex
	logger      api.Logger
}

// NewRegistry creates a new trigger registry
func NewRegistry(logger api.Logger) *Registry {
	return &Registry{
		definitions: make(map[string]api.TriggerDefinition),
		instances:   make(map[string]api.TriggerInstance),
		logger:      logger,
	}
}

// RegisterDefinition registers a trigger definition
func (r *Registry) RegisterDefinition(pluginID string, definition api.TriggerDefinition) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	fullName := fmt.Sprintf("%s.%s", pluginID, definition.Name)

	if _, exists := r.definitions[fullName]; exists {
		return fmt.Errorf("trigger definition %s already exists", fullName)
	}

	r.definitions[fullName] = definition
	r.logger.Debug("Registered trigger definition", "name", fullName, "plugin", pluginID)
	return nil
}

// CreateInstance creates a new trigger instance
func (r *Registry) CreateInstance(triggerID, definitionName string, config interface{}) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	definition, exists := r.definitions[definitionName]
	if !exists {
		return fmt.Errorf("trigger definition %s not found", definitionName)
	}

	if _, exists := r.instances[triggerID]; exists {
		return fmt.Errorf("trigger instance %s already exists", triggerID)
	}

	instance, err := definition.Factory(config)
	if err != nil {
		return fmt.Errorf("failed to create trigger instance: %w", err)
	}

	r.instances[triggerID] = instance
	r.logger.Debug("Created trigger instance", "id", triggerID, "definition", definitionName)
	return nil
}

// ExecuteTrigger executes a trigger by ID
func (r *Registry) ExecuteTrigger(triggerID string, args map[string]interface{}) error {
	r.mutex.RLock()
	instance, exists := r.instances[triggerID]
	r.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("trigger instance %s not found", triggerID)
	}

	return instance.Execute(args)
}

// GetInstance returns a trigger instance by ID
func (r *Registry) GetInstance(triggerID string) (api.TriggerInstance, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	instance, exists := r.instances[triggerID]
	return instance, exists
}

// GetDefinition returns a trigger definition by name
func (r *Registry) GetDefinition(name string) (api.TriggerDefinition, bool) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	definition, exists := r.definitions[name]
	return definition, exists
}

// GetAllDefinitions returns all trigger definitions
func (r *Registry) GetAllDefinitions() map[string]api.TriggerDefinition {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make(map[string]api.TriggerDefinition)
	for k, v := range r.definitions {
		result[k] = v
	}
	return result
}

// GetAllInstances returns all trigger instances
func (r *Registry) GetAllInstances() map[string]api.TriggerInstance {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make(map[string]api.TriggerInstance)
	for k, v := range r.instances {
		result[k] = v
	}
	return result
}

// RemoveInstance removes a trigger instance
func (r *Registry) RemoveInstance(triggerID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.instances[triggerID]; !exists {
		return fmt.Errorf("trigger instance %s not found", triggerID)
	}

	delete(r.instances, triggerID)
	r.logger.Debug("Removed trigger instance", "id", triggerID)
	return nil
}
