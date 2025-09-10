package api

import (
	"sync"
	"time"
)

// TimeWindowTracker manages time-based tracking with automatic cleanup
type TimeWindowTracker[T any] struct {
	entries       map[string]*TimeWindowEntry[T]
	mutex         sync.RWMutex
	timeWindow    time.Duration
	maxHits       int
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
	onThreshold   func(key string, entry *TimeWindowEntry[T])
	logger        Logger
	cleanupMutex  sync.Mutex // Separate mutex for cleanup operations
}

// TimeWindowEntry represents an entry in the time window tracker
type TimeWindowEntry[T any] struct {
	Key       string
	Data      T
	HitCount  int
	FirstSeen time.Time
	LastSeen  time.Time
	Metadata  map[string]interface{}
	mutex     sync.RWMutex // Per-entry mutex for fine-grained locking
}

// TimeWindowConfig configures the time window tracker
type TimeWindowConfig struct {
	TimeWindow      time.Duration
	MaxHits         int
	CleanupInterval time.Duration
}

// NewTimeWindowTracker creates a new time window tracker
func NewTimeWindowTracker[T any](
	config TimeWindowConfig,
	onThreshold func(key string, entry *TimeWindowEntry[T]),
	logger Logger,
) *TimeWindowTracker[T] {
	// Set reasonable defaults for cleanup interval
	cleanupInterval := config.CleanupInterval
	if cleanupInterval == 0 {
		cleanupInterval = config.TimeWindow / 2
		if cleanupInterval < time.Minute {
			cleanupInterval = time.Minute
		}
	}

	return &TimeWindowTracker[T]{
		entries:     make(map[string]*TimeWindowEntry[T]),
		timeWindow:  config.TimeWindow,
		maxHits:     config.MaxHits,
		stopChan:    make(chan struct{}),
		onThreshold: onThreshold,
		logger:      logger,
	}
}

// Start starts the time window tracker
func (twt *TimeWindowTracker[T]) Start() {
	cleanupInterval := twt.timeWindow / 2 // Cleanup twice per window
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute // Minimum 1 minute
	}

	twt.cleanupTicker = time.NewTicker(cleanupInterval)

	go twt.cleanupLoop()

	twt.logger.Debug("TimeWindowTracker started",
		"time_window", twt.timeWindow,
		"max_hits", twt.maxHits,
		"cleanup_interval", cleanupInterval)
}

// Stop stops the time window tracker
func (twt *TimeWindowTracker[T]) Stop() {
	close(twt.stopChan)
	if twt.cleanupTicker != nil {
		twt.cleanupTicker.Stop()
	}
	twt.logger.Debug("TimeWindowTracker stopped")
}

// Track adds or updates an entry
func (twt *TimeWindowTracker[T]) Track(key string, data T, metadata map[string]interface{}) bool {
	now := time.Now()

	// First, try to get existing entry with read lock
	twt.mutex.RLock()
	entry, exists := twt.entries[key]
	twt.mutex.RUnlock()

	if !exists {
		// Create new entry with write lock
		twt.mutex.Lock()
		// Double-check in case another goroutine created it
		if entry, exists = twt.entries[key]; !exists {
			entry = &TimeWindowEntry[T]{
				Key:       key,
				Data:      data,
				HitCount:  0,
				FirstSeen: now,
				Metadata:  make(map[string]interface{}),
			}
			twt.entries[key] = entry
		}
		twt.mutex.Unlock()
	}

	// Update entry with its own mutex
	entry.mutex.Lock()
	entry.Data = data
	entry.LastSeen = now
	entry.HitCount++

	// Update metadata safely
	if metadata != nil {
		for k, v := range metadata {
			entry.Metadata[k] = v
		}
	}

	// Check threshold
	thresholdReached := entry.HitCount >= twt.maxHits
	if thresholdReached {
		twt.logger.Debug("Threshold reached",
			"key", key,
			"hits", entry.HitCount,
			"max_hits", twt.maxHits)

		// Reset hit count but keep tracking
		entry.HitCount = 0
	}
	entry.mutex.Unlock()

	// Call threshold callback outside of locks
	if thresholdReached && twt.onThreshold != nil {
		// Create a copy of the entry for the callback to avoid race conditions
		entryCopy := twt.copyEntry(entry)
		go twt.onThreshold(key, entryCopy)
	}

	return thresholdReached
}

// copyEntry creates a safe copy of an entry for callback use
func (twt *TimeWindowTracker[T]) copyEntry(entry *TimeWindowEntry[T]) *TimeWindowEntry[T] {
	entry.mutex.RLock()
	defer entry.mutex.RUnlock()

	// Create a copy of metadata
	metadataCopy := make(map[string]interface{})
	for k, v := range entry.Metadata {
		metadataCopy[k] = v
	}

	return &TimeWindowEntry[T]{
		Key:       entry.Key,
		Data:      entry.Data,
		HitCount:  entry.HitCount,
		FirstSeen: entry.FirstSeen,
		LastSeen:  entry.LastSeen,
		Metadata:  metadataCopy,
	}
}

// Get retrieves an entry
func (twt *TimeWindowTracker[T]) Get(key string) (*TimeWindowEntry[T], bool) {
	twt.mutex.RLock()
	entry, exists := twt.entries[key]
	twt.mutex.RUnlock()

	if !exists {
		return nil, false
	}

	// Check if entry is still valid
	entry.mutex.RLock()
	isValid := time.Since(entry.LastSeen) <= twt.timeWindow
	entryCopy := twt.copyEntryUnlocked(entry)
	entry.mutex.RUnlock()

	if !isValid {
		return nil, false
	}

	return entryCopy, true
}

// copyEntryUnlocked creates a copy without locking (assumes caller has lock)
func (twt *TimeWindowTracker[T]) copyEntryUnlocked(entry *TimeWindowEntry[T]) *TimeWindowEntry[T] {
	metadataCopy := make(map[string]interface{})
	for k, v := range entry.Metadata {
		metadataCopy[k] = v
	}

	return &TimeWindowEntry[T]{
		Key:       entry.Key,
		Data:      entry.Data,
		HitCount:  entry.HitCount,
		FirstSeen: entry.FirstSeen,
		LastSeen:  entry.LastSeen,
		Metadata:  metadataCopy,
	}
}

// GetAll returns all valid entries
func (twt *TimeWindowTracker[T]) GetAll() map[string]*TimeWindowEntry[T] {
	result := make(map[string]*TimeWindowEntry[T])
	now := time.Now()

	// Get all keys first
	twt.mutex.RLock()
	keys := make([]string, 0, len(twt.entries))
	for key := range twt.entries {
		keys = append(keys, key)
	}
	twt.mutex.RUnlock()

	// Process each entry
	for _, key := range keys {
		twt.mutex.RLock()
		entry, exists := twt.entries[key]
		twt.mutex.RUnlock()

		if !exists {
			continue
		}

		entry.mutex.RLock()
		if now.Sub(entry.LastSeen) <= twt.timeWindow {
			result[key] = twt.copyEntryUnlocked(entry)
		}
		entry.mutex.RUnlock()
	}

	return result
}

// Remove removes an entry
func (twt *TimeWindowTracker[T]) Remove(key string) {
	twt.mutex.Lock()
	delete(twt.entries, key)
	twt.mutex.Unlock()
}

// cleanupLoop runs the cleanup process
func (twt *TimeWindowTracker[T]) cleanupLoop() {
	for {
		select {
		case <-twt.cleanupTicker.C:
			twt.cleanup()
		case <-twt.stopChan:
			return
		}
	}
}

// cleanup removes expired entries
func (twt *TimeWindowTracker[T]) cleanup() {
	twt.cleanupMutex.Lock()
	defer twt.cleanupMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-twt.timeWindow)

	// First pass: identify expired keys
	var expiredKeys []string

	twt.mutex.RLock()
	for key, entry := range twt.entries {
		entry.mutex.RLock()
		if entry.LastSeen.Before(cutoff) {
			expiredKeys = append(expiredKeys, key)
		}
		entry.mutex.RUnlock()
	}
	twt.mutex.RUnlock()

	// Second pass: remove expired entries
	if len(expiredKeys) > 0 {
		twt.mutex.Lock()
		for _, key := range expiredKeys {
			// Double-check before deletion
			if entry, exists := twt.entries[key]; exists {
				entry.mutex.RLock()
				stillExpired := entry.LastSeen.Before(cutoff)
				entry.mutex.RUnlock()

				if stillExpired {
					delete(twt.entries, key)
				}
			}
		}
		remaining := len(twt.entries)
		twt.mutex.Unlock()

		twt.logger.Debug("Cleaned up expired entries",
			"removed", len(expiredKeys),
			"remaining", remaining)
	}
}

// GetStats returns statistics about the tracker
func (twt *TimeWindowTracker[T]) GetStats() map[string]interface{} {
	twt.mutex.RLock()
	entryCount := len(twt.entries)

	totalHits := 0
	for _, entry := range twt.entries {
		entry.mutex.RLock()
		totalHits += entry.HitCount
		entry.mutex.RUnlock()
	}
	twt.mutex.RUnlock()

	return map[string]interface{}{
		"active_entries": entryCount,
		"total_hits":     totalHits,
		"time_window":    twt.timeWindow.Seconds(),
		"max_hits":       twt.maxHits,
	}
}

// Clear removes all entries (useful for testing)
func (twt *TimeWindowTracker[T]) Clear() {
	twt.mutex.Lock()
	twt.entries = make(map[string]*TimeWindowEntry[T])
	twt.mutex.Unlock()

	twt.logger.Debug("Cleared all entries")
}
