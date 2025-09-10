package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/sammwyy/spear/api"
)

// EventBus manages event distribution via Unix Domain Socket
type EventBus struct {
	socketPath  string
	listener    net.Listener
	subscribers []subscription
	mutex       sync.RWMutex
	logger      api.Logger
	ctx         context.Context
	cancel      context.CancelFunc
}

type subscription struct {
	filter  api.EventFilter
	handler api.EventHandler
}

// NewEventBus creates a new event bus
func NewEventBus(socketPath string, logger api.Logger) *EventBus {
	ctx, cancel := context.WithCancel(context.Background())
	return &EventBus{
		socketPath:  socketPath,
		subscribers: make([]subscription, 0),
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start starts the event bus and begins listening for connections
func (eb *EventBus) Start() error {
	// Remove existing socket file if it exists
	if err := os.RemoveAll(eb.socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create the socket
	listener, err := net.Listen("unix", eb.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}

	eb.listener = listener
	eb.logger.Info("EventBus started", "socket", eb.socketPath)

	// Start accepting connections
	go eb.acceptConnections()

	return nil
}

// Stop stops the event bus
func (eb *EventBus) Stop() error {
	eb.cancel()
	if eb.listener != nil {
		if err := eb.listener.Close(); err != nil {
			eb.logger.Error("Failed to close listener", "error", err)
		}
	}

	// Remove socket file
	if err := os.Remove(eb.socketPath); err != nil && !os.IsNotExist(err) {
		eb.logger.Error("Failed to remove socket file", "error", err)
	}

	eb.logger.Info("EventBus stopped")
	return nil
}

// EmitEvent emits an event to all subscribers
func (eb *EventBus) EmitEvent(event api.Event) error {
	eb.mutex.RLock()
	defer eb.mutex.RUnlock()

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Distribute to subscribers
	for _, sub := range eb.subscribers {
		if eb.matchesFilter(event, sub.filter) {
			go func(handler api.EventHandler) {
				if err := handler(event); err != nil {
					eb.logger.Error("Event handler failed", "error", err, "event_id", event.ID)
				}
			}(sub.handler)
		}
	}

	return nil
}

// SubscribeToEvents subscribes to events matching the given filter
func (eb *EventBus) SubscribeToEvents(filter api.EventFilter, handler api.EventHandler) error {
	eb.mutex.Lock()
	defer eb.mutex.Unlock()

	eb.subscribers = append(eb.subscribers, subscription{
		filter:  filter,
		handler: handler,
	})

	eb.logger.Debug("New event subscription added", "filter", filter)
	return nil
}

// acceptConnections accepts incoming socket connections
func (eb *EventBus) acceptConnections() {
	for {
		select {
		case <-eb.ctx.Done():
			return
		default:
			conn, err := eb.listener.Accept()
			if err != nil {
				select {
				case <-eb.ctx.Done():
					return
				default:
					eb.logger.Error("Failed to accept connection", "error", err)
					continue
				}
			}

			go eb.handleConnection(conn)
		}
	}
}

// handleConnection handles a single socket connection
func (eb *EventBus) handleConnection(conn net.Conn) {
	defer conn.Close()

	decoder := json.NewDecoder(conn)

	for {
		var event api.Event
		if err := decoder.Decode(&event); err != nil {
			if err.Error() != "EOF" {
				eb.logger.Error("Failed to decode event", "error", err)
			}
			return
		}

		if err := eb.EmitEvent(event); err != nil {
			eb.logger.Error("Failed to emit event", "error", err)
		}
	}
}

// matchesFilter checks if an event matches the given filter
func (eb *EventBus) matchesFilter(event api.Event, filter api.EventFilter) bool {
	// Check sources filter
	if len(filter.Sources) > 0 {
		found := false
		for _, source := range filter.Sources {
			if event.Source == source {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check types filter
	if len(filter.Types) > 0 {
		found := false
		for _, eventType := range filter.Types {
			if event.Type == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check regex filters
	for field, pattern := range filter.Regex {
		var fieldValue string

		switch field {
		case "source":
			fieldValue = event.Source
		case "type":
			fieldValue = event.Type
		default:
			// Check in payload
			if val, exists := event.Payload[field]; exists {
				fieldValue = fmt.Sprintf("%v", val)
			}
		}

		matched, err := regexp.MatchString(pattern, fieldValue)
		if err != nil {
			eb.logger.Error("Invalid regex pattern", "pattern", pattern, "error", err)
			return false
		}

		if !matched {
			return false
		}
	}

	return true
}
