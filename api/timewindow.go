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
}

// TimeWindowEntry represents an entry in the time window tracker
type TimeWindowEntry[T any] struct {
	Key       string
	Data      T
	HitCount  int
	FirstSeen time.Time
	LastSeen  time.Time
	Metadata  map[string]interface{}
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

	go func() {
		for {
			select {
			case <-twt.cleanupTicker.C:
				twt.cleanup()
			case <-twt.stopChan:
				return
			}
		}
	}()

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
	twt.mutex.Lock()
	defer twt.mutex.Unlock()

	now := time.Now()

	entry, exists := twt.entries[key]
	if !exists {
		entry = &TimeWindowEntry[T]{
			Key:       key,
			Data:      data,
			HitCount:  0,
			FirstSeen: now,
			Metadata:  make(map[string]interface{}),
		}
		twt.entries[key] = entry
	}

	// Update entry
	entry.Data = data
	entry.LastSeen = now
	entry.HitCount++

	// Update metadata
	if metadata != nil {
		for k, v := range metadata {
			entry.Metadata[k] = v
		}
	}

	// Check if threshold is reached
	if entry.HitCount >= twt.maxHits {
		twt.logger.Debug("Threshold reached",
			"key", key,
			"hits", entry.HitCount,
			"max_hits", twt.maxHits)

		// Call threshold callback
		if twt.onThreshold != nil {
			go twt.onThreshold(key, entry)
		}

		// Reset hit count but keep tracking
		entry.HitCount = 0
		return true
	}

	return false
}

// Get retrieves an entry
func (twt *TimeWindowTracker[T]) Get(key string) (*TimeWindowEntry[T], bool) {
	twt.mutex.RLock()
	defer twt.mutex.RUnlock()

	entry, exists := twt.entries[key]
	if !exists {
		return nil, false
	}

	// Check if entry is still valid
	if time.Since(entry.LastSeen) > twt.timeWindow {
		return nil, false
	}

	return entry, true
}

// GetAll returns all valid entries
func (twt *TimeWindowTracker[T]) GetAll() map[string]*TimeWindowEntry[T] {
	twt.mutex.RLock()
	defer twt.mutex.RUnlock()

	result := make(map[string]*TimeWindowEntry[T])
	now := time.Now()

	for key, entry := range twt.entries {
		if now.Sub(entry.LastSeen) <= twt.timeWindow {
			result[key] = entry
		}
	}

	return result
}

// Remove removes an entry
func (twt *TimeWindowTracker[T]) Remove(key string) {
	twt.mutex.Lock()
	defer twt.mutex.Unlock()

	delete(twt.entries, key)
}

// cleanup removes expired entries
func (twt *TimeWindowTracker[T]) cleanup() {
	twt.mutex.Lock()
	defer twt.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-twt.timeWindow)
	removedCount := 0

	for key, entry := range twt.entries {
		if entry.LastSeen.Before(cutoff) {
			delete(twt.entries, key)
			removedCount++
		}
	}

	if removedCount > 0 {
		twt.logger.Debug("Cleaned up expired entries",
			"removed", removedCount,
			"remaining", len(twt.entries))
	}
}

// GetStats returns statistics about the tracker
func (twt *TimeWindowTracker[T]) GetStats() map[string]interface{} {
	twt.mutex.RLock()
	defer twt.mutex.RUnlock()

	totalHits := 0
	for _, entry := range twt.entries {
		totalHits += entry.HitCount
	}

	return map[string]interface{}{
		"active_entries": len(twt.entries),
		"total_hits":     totalHits,
		"time_window":    twt.timeWindow.Seconds(),
		"max_hits":       twt.maxHits,
	}
}
