package api

import (
	"sync"
	"sync/atomic"
	"time"
)

// AsyncTimeWindowTracker manages time-based tracking with async processing
type AsyncTimeWindowTracker[T any] struct {
	entries     sync.Map // Using sync.Map for lock-free reads
	timeWindow  time.Duration
	maxHits     int
	onThreshold func(key string, entry *TimeWindowEntry[T])
	logger      Logger

	// Async processing
	eventQueue    chan *TrackingEvent[T]
	stopChan      chan struct{}
	workerPool    []*Worker[T]
	numWorkers    int
	cleanupTicker *time.Ticker

	// Stats
	queueSize int64
	processed int64
	dropped   int64
}

// TrackingEvent represents an event to be processed
type TrackingEvent[T any] struct {
	Key       string
	Data      T
	Metadata  map[string]interface{}
	Timestamp time.Time
}

// Worker processes tracking events
type Worker[T any] struct {
	id      int
	tracker *AsyncTimeWindowTracker[T]
	queue   chan *TrackingEvent[T]
	stop    chan struct{}
}

// TimeWindowEntry with atomic operations
type TimeWindowEntry[T any] struct {
	Key       string
	Data      T
	HitCount  int64 // Using atomic operations
	FirstSeen time.Time
	LastSeen  time.Time
	Metadata  sync.Map // Using sync.Map for metadata
}

// AsyncTimeWindowConfig configures the async tracker
type AsyncTimeWindowConfig struct {
	TimeWindow      time.Duration
	MaxHits         int
	CleanupInterval time.Duration
	QueueSize       int // Buffer size for event queue
	NumWorkers      int // Number of worker goroutines
}

// NewAsyncTimeWindowTracker creates a new async time window tracker
func NewAsyncTimeWindowTracker[T any](
	config AsyncTimeWindowConfig,
	onThreshold func(key string, entry *TimeWindowEntry[T]),
	logger Logger,
) *AsyncTimeWindowTracker[T] {
	// Set defaults
	if config.QueueSize == 0 {
		config.QueueSize = 10000
	}
	if config.NumWorkers == 0 {
		config.NumWorkers = 4
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = config.TimeWindow / 2
		if config.CleanupInterval < time.Minute {
			config.CleanupInterval = time.Minute
		}
	}

	tracker := &AsyncTimeWindowTracker[T]{
		timeWindow:  config.TimeWindow,
		maxHits:     config.MaxHits,
		onThreshold: onThreshold,
		logger:      logger,
		eventQueue:  make(chan *TrackingEvent[T], config.QueueSize),
		stopChan:    make(chan struct{}),
		numWorkers:  config.NumWorkers,
	}

	return tracker
}

// Start starts the async tracker
func (awt *AsyncTimeWindowTracker[T]) Start() {
	// Start worker pool
	awt.workerPool = make([]*Worker[T], awt.numWorkers)
	for i := 0; i < awt.numWorkers; i++ {
		worker := &Worker[T]{
			id:      i,
			tracker: awt,
			queue:   make(chan *TrackingEvent[T], 100),
			stop:    make(chan struct{}),
		}
		awt.workerPool[i] = worker
		go worker.run()
	}

	// Start event dispatcher
	go awt.eventDispatcher()

	// Start cleanup
	cleanupInterval := awt.timeWindow / 2
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute
	}
	awt.cleanupTicker = time.NewTicker(cleanupInterval)
	go awt.cleanupLoop()

	awt.logger.Debug("AsyncTimeWindowTracker started",
		"workers", awt.numWorkers,
		"queue_size", cap(awt.eventQueue))
}

// Stop stops the async tracker
func (awt *AsyncTimeWindowTracker[T]) Stop() {
	close(awt.stopChan)

	// Stop workers
	for _, worker := range awt.workerPool {
		close(worker.stop)
	}

	if awt.cleanupTicker != nil {
		awt.cleanupTicker.Stop()
	}

	awt.logger.Debug("AsyncTimeWindowTracker stopped")
}

// Track adds an event to the queue (non-blocking)
func (awt *AsyncTimeWindowTracker[T]) Track(key string, data T, metadata map[string]interface{}) bool {
	event := &TrackingEvent[T]{
		Key:       key,
		Data:      data,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	select {
	case awt.eventQueue <- event:
		atomic.AddInt64(&awt.queueSize, 1)
		return true
	default:
		// Queue is full, drop the event and log
		atomic.AddInt64(&awt.dropped, 1)
		awt.logger.Warn("Event queue full, dropping event", "key", key)
		return false
	}
}

// eventDispatcher distributes events to workers using round-robin
func (awt *AsyncTimeWindowTracker[T]) eventDispatcher() {
	workerIndex := 0

	for {
		select {
		case event := <-awt.eventQueue:
			atomic.AddInt64(&awt.queueSize, -1)

			// Round-robin distribution
			worker := awt.workerPool[workerIndex]
			workerIndex = (workerIndex + 1) % awt.numWorkers

			select {
			case worker.queue <- event:
				// Event sent to worker
			default:
				// Worker queue full, try next worker
				nextWorker := awt.workerPool[(workerIndex)%awt.numWorkers]
				select {
				case nextWorker.queue <- event:
					// Event sent to next worker
				default:
					// All workers busy, drop event
					atomic.AddInt64(&awt.dropped, 1)
					awt.logger.Warn("All workers busy, dropping event", "key", event.Key)
				}
			}

		case <-awt.stopChan:
			return
		}
	}
}

// Worker methods
func (w *Worker[T]) run() {
	for {
		select {
		case event := <-w.queue:
			w.processEvent(event)
			atomic.AddInt64(&w.tracker.processed, 1)

		case <-w.stop:
			return
		}
	}
}

func (w *Worker[T]) processEvent(event *TrackingEvent[T]) {
	now := event.Timestamp

	// Get or create entry
	var entry *TimeWindowEntry[T]
	if value, exists := w.tracker.entries.Load(event.Key); exists {
		entry = value.(*TimeWindowEntry[T])
	} else {
		entry = &TimeWindowEntry[T]{
			Key:       event.Key,
			Data:      event.Data,
			FirstSeen: now,
		}

		// Try to store, if another goroutine stored it first, use that one
		if actual, loaded := w.tracker.entries.LoadOrStore(event.Key, entry); loaded {
			entry = actual.(*TimeWindowEntry[T])
		}
	}

	// Update entry atomically
	entry.Data = event.Data
	entry.LastSeen = now
	hitCount := atomic.AddInt64(&entry.HitCount, 1)

	// Update metadata
	if event.Metadata != nil {
		for k, v := range event.Metadata {
			entry.Metadata.Store(k, v)
		}
	}

	// Check threshold
	if int(hitCount) >= w.tracker.maxHits {
		w.tracker.logger.Debug("Threshold reached",
			"key", event.Key,
			"hits", hitCount,
			"max_hits", w.tracker.maxHits,
			"worker", w.id)

		// Reset count and trigger callback
		atomic.StoreInt64(&entry.HitCount, 0)

		if w.tracker.onThreshold != nil {
			// Create safe copy for callback
			entryCopy := w.copyEntry(entry)
			// Run callback in separate goroutine to avoid blocking worker
			go w.tracker.onThreshold(event.Key, entryCopy)
		}
	}
}

func (w *Worker[T]) copyEntry(entry *TimeWindowEntry[T]) *TimeWindowEntry[T] {
	metadataCopy := make(map[string]interface{})
	entry.Metadata.Range(func(key, value interface{}) bool {
		metadataCopy[key.(string)] = value
		return true
	})

	return &TimeWindowEntry[T]{
		Key:       entry.Key,
		Data:      entry.Data,
		HitCount:  atomic.LoadInt64(&entry.HitCount),
		FirstSeen: entry.FirstSeen,
		LastSeen:  entry.LastSeen,
		Metadata:  sync.Map{},
	}
}

// Get retrieves an entry (lock-free)
func (awt *AsyncTimeWindowTracker[T]) Get(key string) (*TimeWindowEntry[T], bool) {
	value, exists := awt.entries.Load(key)
	if !exists {
		return nil, false
	}

	entry := value.(*TimeWindowEntry[T])

	// Check if still valid
	if time.Since(entry.LastSeen) > awt.timeWindow {
		return nil, false
	}

	// Create safe copy
	metadataCopy := make(map[string]interface{})
	entry.Metadata.Range(func(key, value interface{}) bool {
		metadataCopy[key.(string)] = value
		return true
	})

	return &TimeWindowEntry[T]{
		Key:       entry.Key,
		Data:      entry.Data,
		HitCount:  atomic.LoadInt64(&entry.HitCount),
		FirstSeen: entry.FirstSeen,
		LastSeen:  entry.LastSeen,
		Metadata:  sync.Map{},
	}, true
}

// cleanupLoop removes expired entries
func (awt *AsyncTimeWindowTracker[T]) cleanupLoop() {
	for {
		select {
		case <-awt.cleanupTicker.C:
			awt.cleanup()
		case <-awt.stopChan:
			return
		}
	}
}

func (awt *AsyncTimeWindowTracker[T]) cleanup() {
	now := time.Now()
	cutoff := now.Add(-awt.timeWindow)
	removed := 0

	awt.entries.Range(func(key, value interface{}) bool {
		entry := value.(*TimeWindowEntry[T])
		if entry.LastSeen.Before(cutoff) {
			awt.entries.Delete(key)
			removed++
		}
		return true
	})

	if removed > 0 {
		awt.logger.Debug("Cleaned up expired entries", "removed", removed)
	}
}

// GetStats returns performance statistics
func (awt *AsyncTimeWindowTracker[T]) GetStats() map[string]interface{} {
	entryCount := 0
	awt.entries.Range(func(key, value interface{}) bool {
		entryCount++
		return true
	})

	return map[string]interface{}{
		"active_entries": entryCount,
		"queue_size":     atomic.LoadInt64(&awt.queueSize),
		"processed":      atomic.LoadInt64(&awt.processed),
		"dropped":        atomic.LoadInt64(&awt.dropped),
		"workers":        awt.numWorkers,
		"time_window":    awt.timeWindow.Seconds(),
		"max_hits":       awt.maxHits,
	}
}
