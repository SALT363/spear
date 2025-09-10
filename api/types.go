package api

import (
	"reflect"
	"time"
)

// Event represents a system event
type Event struct {
	ID        string                 `json:"id"`
	Source    string                 `json:"source"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload"`
}

// EventFilter defines criteria for filtering events
type EventFilter struct {
	Sources []string          `json:"sources,omitempty"`
	Types   []string          `json:"types,omitempty"`
	Regex   map[string]string `json:"regex,omitempty"`
}

// EventHandler is a function that processes events
type EventHandler func(event Event) error

// TriggerDefinition defines a trigger that can be registered by plugins
type TriggerDefinition struct {
	Name        string
	Description string
	ConfigType  reflect.Type
	Factory     func(config interface{}) (TriggerInstance, error)
}

// TriggerInstance represents an instantiated trigger
type TriggerInstance interface {
	ID() string
	Execute(args map[string]interface{}) error
	GetArgumentSchema() map[string]ArgumentSpec
}

// ArgumentSpec defines the specification for trigger arguments
type ArgumentSpec struct {
	Type        string      `json:"type"`
	Required    bool        `json:"required"`
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
}

// ModuleDefinition defines a module that can be registered by plugins
type ModuleDefinition struct {
	Name        string
	Description string
	ConfigType  reflect.Type
	Factory     func(config interface{}) (ModuleInstance, error)
}

// ModuleInstance represents an instantiated module
type ModuleInstance interface {
	ID() string
	Start() error
	Stop() error
	HandleEvent(event Event) error
}

// PluginMeta contains metadata about a plugin
type PluginMeta struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Author      string `json:"author"`
	Repository  string `json:"repository"`
	Description string `json:"description"`
	Version     string `json:"version"`
}
