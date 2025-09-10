package filewatcher

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sammwyy/spear/api"
)

// FileWatcher watches files for changes and distributes events to modules
type FileWatcher struct {
	watcher     *fsnotify.Watcher
	watchers    map[string]*fileWatch
	mutex       sync.RWMutex
	logger      api.Logger
	eventBus    api.CoreAPI
	stopChannel chan struct{}
}

type fileWatch struct {
	filePath string
	file     *os.File
	scanner  *bufio.Scanner
	modules  []moduleRegistration
	position int64
}

type moduleRegistration struct {
	module ModuleInstance
	regex  *regexp.Regexp
}

type ModuleInstance interface {
	ID() string
	HandleEvent(event api.Event) error
}

// NewFileWatcher creates a new file watcher
func NewFileWatcher(logger api.Logger, eventBus api.CoreAPI) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	return &FileWatcher{
		watcher:     watcher,
		watchers:    make(map[string]*fileWatch),
		logger:      logger,
		eventBus:    eventBus,
		stopChannel: make(chan struct{}),
	}, nil
}

// Start starts the file watcher
func (fw *FileWatcher) Start() error {
	go fw.watchLoop()
	fw.logger.Info("FileWatcher started")
	return nil
}

// Stop stops the file watcher
func (fw *FileWatcher) Stop() error {
	close(fw.stopChannel)

	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	// Close all file handles
	for _, watch := range fw.watchers {
		if watch.file != nil {
			watch.file.Close()
		}
	}

	if err := fw.watcher.Close(); err != nil {
		fw.logger.Error("Failed to close fsnotify watcher", "error", err)
	}

	fw.logger.Info("FileWatcher stopped")
	return nil
}

// RegisterModule registers a module to watch a specific file with a regex pattern
func (fw *FileWatcher) RegisterModule(filePath string, module ModuleInstance, regexPattern string) error {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	// Compile regex
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern %s: %w", regexPattern, err)
	}

	// Get or create file watch
	watch, exists := fw.watchers[filePath]
	if !exists {
		// Create new file watch
		watch = &fileWatch{
			filePath: filePath,
			modules:  make([]moduleRegistration, 0),
		}

		// Open file and seek to end
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", filePath, err)
		}

		// Seek to end of file to only read new content
		position, err := file.Seek(0, 2)
		if err != nil {
			file.Close()
			return fmt.Errorf("failed to seek to end of file: %w", err)
		}

		watch.file = file
		watch.position = position
		watch.scanner = bufio.NewScanner(file)
		fw.watchers[filePath] = watch

		// Add to fsnotify watcher
		if err := fw.watcher.Add(filePath); err != nil {
			file.Close()
			delete(fw.watchers, filePath)
			return fmt.Errorf("failed to add file to watcher: %w", err)
		}

		fw.logger.Debug("Started watching file", "path", filePath)
	}

	// Add module registration
	watch.modules = append(watch.modules, moduleRegistration{
		module: module,
		regex:  regex,
	})

	fw.logger.Debug("Registered module for file", "module", module.ID(), "file", filePath, "regex", regexPattern)
	return nil
}

// RegisterModuleWithFallback registers a module to watch files with fallback
// It tries each file path in order and uses the first one that exists
func (fw *FileWatcher) RegisterModuleWithFallback(filePaths []string, module ModuleInstance, regexPattern string) error {
	var lastErr error

	for _, filePath := range filePaths {
		if _, err := os.Stat(filePath); err == nil {
			// File exists, try to register
			if err := fw.RegisterModule(filePath, module, regexPattern); err != nil {
				lastErr = err
				fw.logger.Debug("Failed to register module for file, trying next", "file", filePath, "error", err)
				continue
			}

			fw.logger.Info("Successfully registered module with file", "module", module.ID(), "file", filePath)
			return nil
		} else {
			lastErr = fmt.Errorf("file %s does not exist: %w", filePath, err)
			fw.logger.Debug("File does not exist, trying next", "file", filePath)
		}
	}

	return fmt.Errorf("no valid file found for module %s from paths %v: %w", module.ID(), filePaths, lastErr)
}

// UnregisterModule unregisters a module from watching a file
func (fw *FileWatcher) UnregisterModule(filePath string, moduleID string) error {
	fw.mutex.Lock()
	defer fw.mutex.Unlock()

	watch, exists := fw.watchers[filePath]
	if !exists {
		return fmt.Errorf("file %s is not being watched", filePath)
	}

	// Remove module from list
	newModules := make([]moduleRegistration, 0)
	found := false
	for _, reg := range watch.modules {
		if reg.module.ID() != moduleID {
			newModules = append(newModules, reg)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("module %s not registered for file %s", moduleID, filePath)
	}

	watch.modules = newModules

	// If no modules left, stop watching file
	if len(watch.modules) == 0 {
		fw.watcher.Remove(filePath)
		if watch.file != nil {
			watch.file.Close()
		}
		delete(fw.watchers, filePath)
		fw.logger.Debug("Stopped watching file", "path", filePath)
	}

	fw.logger.Debug("Unregistered module from file", "module", moduleID, "file", filePath)
	return nil
}

// watchLoop is the main event loop for file watching
func (fw *FileWatcher) watchLoop() {
	for {
		select {
		case <-fw.stopChannel:
			return
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write {
				fw.handleFileWrite(event.Name)
			}
		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			fw.logger.Error("File watcher error", "error", err)
		}
	}
}

// handleFileWrite handles a file write event
func (fw *FileWatcher) handleFileWrite(filePath string) {
	fw.mutex.RLock()
	watch, exists := fw.watchers[filePath]
	fw.mutex.RUnlock()

	if !exists {
		return
	}

	// Read new lines from file
	lines := fw.readNewLines(watch)

	// Process each line
	for _, line := range lines {
		fw.processLine(filePath, line, watch.modules)
	}
}

// readNewLines reads new lines from the file since last position
func (fw *FileWatcher) readNewLines(watch *fileWatch) []string {
	// Reopen file to get current content
	file, err := os.Open(watch.filePath)
	if err != nil {
		fw.logger.Error("Failed to reopen file", "path", watch.filePath, "error", err)
		return nil
	}
	defer file.Close()

	// Seek to last position
	_, err = file.Seek(watch.position, 0)
	if err != nil {
		fw.logger.Error("Failed to seek in file", "error", err)
		return nil
	}

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fw.logger.Error("Error reading file", "error", err)
		return lines
	}

	// Update position
	newPosition, err := file.Seek(0, 1)
	if err == nil {
		watch.position = newPosition
	}

	return lines
}

// processLine processes a single line from a file
func (fw *FileWatcher) processLine(filePath, line string, modules []moduleRegistration) {
	event := api.Event{
		ID:        fmt.Sprintf("file_%d", time.Now().UnixNano()),
		Source:    fmt.Sprintf("file:%s", filePath),
		Type:      "file_line",
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"file": filePath,
			"line": line,
		},
	}

	// Check which modules are interested in this line
	for _, reg := range modules {
		if reg.regex.MatchString(line) {
			go func(module ModuleInstance, evt api.Event) {
				if err := module.HandleEvent(evt); err != nil {
					fw.logger.Error("Module failed to handle event", "module", module.ID(), "error", err)
				}
			}(reg.module, event)
		}
	}
}
