package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sammwyy/spear/api"
)

// FileWatchPlugin is the main plugin struct
type FileWatchPlugin struct {
	api    api.CoreAPI
	logger api.Logger
}

// FileWatchConfig represents the configuration for a filewatch instance
type FileWatchConfig struct {
	Enabled        bool     `toml:"enabled"`
	Files          []string `toml:"files"`           // Files to watch
	Dirs           []string `toml:"dirs"`            // Directories to watch
	EventTypes     []string `toml:"event_types"`     // Event types to watch
	IncludeContent bool     `toml:"include_content"` // Include file content in events
	IncludeList    bool     `toml:"include_list"`    // Include directory listing in dir events
	Triggers       []string `toml:"triggers"`        // Triggers to execute
	ReadTimeout    int      `toml:"read_timeout"`    // File read timeout in milliseconds
	MaxFileSize    int64    `toml:"max_file_size"`   // Maximum file size to read in bytes
	BufferSize     int      `toml:"buffer_size"`     // Read buffer size
}

// FileWatchModule represents an instance of the filewatch module
type FileWatchModule struct {
	id     string
	config FileWatchConfig
	api    api.CoreAPI
	logger api.Logger

	// File watching infrastructure
	watcher      *fsnotify.Watcher
	stopChan     chan bool
	fileWatchers map[string]*FileWatcher // path -> FileWatcher
	dirWatchers  map[string]*DirWatcher  // dir -> DirWatcher
	watcherMutex sync.RWMutex

	// Event type flags for fast comparison
	eventFlags EventFlags
}

// EventFlags represents event types as boolean flags for fast comparison
type EventFlags struct {
	Create    bool
	Write     bool
	Remove    bool
	Rename    bool
	Chmod     bool
	DirAdd    bool // File added to directory
	DirRemove bool // File removed from directory
	DirChange bool // Directory contents changed
}

// FileWatcher represents a watcher for a specific file
type FileWatcher struct {
	path     string
	exists   bool
	lastStat os.FileInfo
}

// DirWatcher represents a watcher for a directory
type DirWatcher struct {
	path        string
	isTargetDir bool            // True if this is a configured directory, false if watching for file creation
	targetFiles map[string]bool // Files we're waiting for (only for file watchers)
	lastListing map[string]bool // Last directory listing (only for target dirs)
}

// FileEvent represents a file system event
type FileEvent struct {
	Type        string // create, write, remove, rename, chmod, dir_add, dir_remove, dir_change
	Path        string // File or directory path
	TargetPath  string // For directory events, the file that triggered it
	Timestamp   time.Time
	Size        int64
	Mode        os.FileMode
	Content     string
	Error       string
	ModuleID    string
	IsDirectory bool
	DirListing  []string // Directory listing (if include_list is true)
}

// NewPlugin creates a new filewatch plugin instance
func NewPlugin() api.Plugin {
	return &FileWatchPlugin{}
}

// Meta returns plugin metadata
func (p *FileWatchPlugin) Meta() api.PluginMeta {
	return api.PluginMeta{
		ID:          "filewatch",
		DisplayName: "File System Watcher",
		Author:      "Spear Team",
		Repository:  "https://github.com/sammwyy/spear",
		Description: "Monitors file system events for files and directories with intelligent fallback",
		Version:     "1.0.0",
	}
}

// Initialize initializes the plugin
func (p *FileWatchPlugin) Initialize(apiInstance api.CoreAPI) error {
	p.api = apiInstance
	p.logger = apiInstance.GetLogger("filewatch")
	p.logger.Info("FileWatch plugin initialized")
	return nil
}

// Shutdown shuts down the plugin
func (p *FileWatchPlugin) Shutdown() error {
	p.logger.Info("FileWatch plugin shutting down")
	return nil
}

// ValidateConfig validates the plugin configuration
func (p *FileWatchPlugin) ValidateConfig(config interface{}) error {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid config type for filewatch")
	}

	// Check if enabled
	if enabled, exists := configMap["enabled"]; exists {
		if e, ok := enabled.(bool); ok && !e {
			return nil // Disabled modules don't need further validation
		}
	}

	// Must have either files or dirs
	hasFiles := false
	hasDirs := false

	if files, exists := configMap["files"]; exists {
		if fileList, ok := files.([]interface{}); ok && len(fileList) > 0 {
			hasFiles = true
		}
	}

	if dirs, exists := configMap["dirs"]; exists {
		if dirList, ok := dirs.([]interface{}); ok && len(dirList) > 0 {
			hasDirs = true
		}
	}

	if !hasFiles && !hasDirs {
		return fmt.Errorf("filewatch config must specify at least one file or directory to watch")
	}

	// Validate event types
	if eventTypes, exists := configMap["event_types"]; exists {
		if etList, ok := eventTypes.([]interface{}); ok {
			for _, et := range etList {
				if etStr, ok := et.(string); ok {
					if !p.isValidEventType(etStr) {
						return fmt.Errorf("invalid event type: %s", etStr)
					}
				}
			}
		}
	}

	// Validate timeouts and sizes
	if readTimeout, exists := configMap["read_timeout"]; exists {
		if rt, ok := readTimeout.(int64); ok && rt < 0 {
			return fmt.Errorf("read_timeout must be positive")
		}
	}

	if maxFileSize, exists := configMap["max_file_size"]; exists {
		if mfs, ok := maxFileSize.(int64); ok && mfs < 0 {
			return fmt.Errorf("max_file_size must be positive")
		}
	}

	return nil
}

// GetConfigSchema returns the configuration schema
func (p *FileWatchPlugin) GetConfigSchema() interface{} {
	return FileWatchConfig{}
}

// RegisterModules returns the modules provided by this plugin
func (p *FileWatchPlugin) RegisterModules() []api.ModuleDefinition {
	return []api.ModuleDefinition{
		{
			Name:        "filewatch",
			Description: "File and directory monitoring module with intelligent fallback",
			ConfigType:  nil,
			Factory:     p.createFileWatchModule,
		},
	}
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *FileWatchPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{}
}

// createFileWatchModule creates a new filewatch module instance
func (p *FileWatchPlugin) createFileWatchModule(config interface{}) (api.ModuleInstance, error) {
	fileConfig, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format")
	}

	// Parse config with defaults
	cfg := FileWatchConfig{
		Enabled:        true,
		Files:          []string{},
		Dirs:           []string{},
		EventTypes:     []string{"create", "write", "remove"},
		IncludeContent: false,
		IncludeList:    false,
		Triggers:       []string{},
		ReadTimeout:    5000,     // 5 seconds
		MaxFileSize:    10485760, // 10MB
		BufferSize:     4096,     // 4KB
	}

	if err := p.parseConfig(fileConfig, &cfg); err != nil {
		return nil, err
	}

	// Check if disabled
	if !cfg.Enabled {
		return nil, fmt.Errorf("filewatch module is disabled")
	}

	// Validate config
	if err := p.ValidateConfig(fileConfig); err != nil {
		return nil, err
	}

	module := &FileWatchModule{
		id:           fmt.Sprintf("filewatch_%d", time.Now().UnixNano()),
		config:       cfg,
		api:          p.api,
		logger:       p.api.GetLogger("filewatch"),
		stopChan:     make(chan bool),
		fileWatchers: make(map[string]*FileWatcher),
		dirWatchers:  make(map[string]*DirWatcher),
		eventFlags:   p.parseEventFlags(cfg.EventTypes),
	}

	return module, nil
}

// parseConfig parses configuration from map to struct
func (p *FileWatchPlugin) parseConfig(configMap map[string]interface{}, cfg *FileWatchConfig) error {
	if enabled, exists := configMap["enabled"]; exists {
		if e, ok := enabled.(bool); ok {
			cfg.Enabled = e
		}
	}

	if files, exists := configMap["files"]; exists {
		if fileSlice, ok := files.([]interface{}); ok {
			cfg.Files = []string{}
			for _, file := range fileSlice {
				cfg.Files = append(cfg.Files, fmt.Sprintf("%v", file))
			}
		}
	}

	if dirs, exists := configMap["dirs"]; exists {
		if dirSlice, ok := dirs.([]interface{}); ok {
			cfg.Dirs = []string{}
			for _, dir := range dirSlice {
				cfg.Dirs = append(cfg.Dirs, fmt.Sprintf("%v", dir))
			}
		}
	}

	if eventTypes, exists := configMap["event_types"]; exists {
		if etSlice, ok := eventTypes.([]interface{}); ok {
			cfg.EventTypes = []string{}
			for _, et := range etSlice {
				cfg.EventTypes = append(cfg.EventTypes, fmt.Sprintf("%v", et))
			}
		}
	}

	if includeContent, exists := configMap["include_content"]; exists {
		if ic, ok := includeContent.(bool); ok {
			cfg.IncludeContent = ic
		}
	}

	if includeList, exists := configMap["include_list"]; exists {
		if il, ok := includeList.(bool); ok {
			cfg.IncludeList = il
		}
	}

	if triggers, exists := configMap["triggers"]; exists {
		if triggerSlice, ok := triggers.([]interface{}); ok {
			cfg.Triggers = []string{}
			for _, trigger := range triggerSlice {
				cfg.Triggers = append(cfg.Triggers, fmt.Sprintf("%v", trigger))
			}
		}
	}

	if readTimeout, exists := configMap["read_timeout"]; exists {
		if rt, ok := readTimeout.(int64); ok {
			cfg.ReadTimeout = int(rt)
		}
	}

	if maxFileSize, exists := configMap["max_file_size"]; exists {
		if mfs, ok := maxFileSize.(int64); ok {
			cfg.MaxFileSize = mfs
		}
	}

	if bufferSize, exists := configMap["buffer_size"]; exists {
		if bs, ok := bufferSize.(int64); ok {
			cfg.BufferSize = int(bs)
		}
	}

	return nil
}

// parseEventFlags converts event type strings to boolean flags
func (p *FileWatchPlugin) parseEventFlags(eventTypes []string) EventFlags {
	flags := EventFlags{}

	for _, eventType := range eventTypes {
		switch eventType {
		case "create":
			flags.Create = true
		case "write":
			flags.Write = true
		case "remove":
			flags.Remove = true
		case "rename":
			flags.Rename = true
		case "chmod":
			flags.Chmod = true
		case "dir_add":
			flags.DirAdd = true
		case "dir_remove":
			flags.DirRemove = true
		case "dir_change":
			flags.DirChange = true
		}
	}

	return flags
}

// isValidEventType checks if an event type is valid
func (p *FileWatchPlugin) isValidEventType(eventType string) bool {
	validTypes := []string{"create", "write", "remove", "rename", "chmod", "dir_add", "dir_remove", "dir_change"}
	for _, valid := range validTypes {
		if eventType == valid {
			return true
		}
	}
	return false
}

// FileWatchModule methods

func (m *FileWatchModule) ID() string {
	return m.id
}

func (m *FileWatchModule) Start() error {
	m.logger.Info("Starting FileWatch module",
		"files_count", len(m.config.Files),
		"dirs_count", len(m.config.Dirs),
		"event_types", m.config.EventTypes,
		"include_content", m.config.IncludeContent,
		"include_list", m.config.IncludeList)

	// Initialize file watcher
	var err error
	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}

	// Setup file watchers
	for _, filePath := range m.config.Files {
		if err := m.setupFileWatch(filePath); err != nil {
			m.logger.Error("Failed to setup file watch", "path", filePath, "error", err)
			continue
		}
	}

	// Setup directory watchers
	for _, dirPath := range m.config.Dirs {
		if err := m.setupDirectoryWatch(dirPath); err != nil {
			m.logger.Error("Failed to setup directory watch", "path", dirPath, "error", err)
			continue
		}
	}

	// Start monitoring goroutine
	go m.monitorEvents()

	return nil
}

func (m *FileWatchModule) Stop() error {
	m.logger.Info("Stopping FileWatch module")

	// Stop the monitoring goroutine
	close(m.stopChan)

	// Close file watcher
	if m.watcher != nil {
		m.watcher.Close()
	}

	return nil
}

func (m *FileWatchModule) HandleEvent(event api.Event) error {
	// This module doesn't handle external events
	return nil
}

// setupFileWatch sets up watching for a specific file
func (m *FileWatchModule) setupFileWatch(path string) error {
	// Check if file exists
	if _, err := os.Stat(path); err == nil {
		// File exists, watch it directly
		return m.watchFile(path)
	} else if os.IsNotExist(err) {
		// File doesn't exist, watch parent directory
		return m.watchDirectoryForFile(path)
	} else {
		return fmt.Errorf("failed to stat file %s: %v", path, err)
	}
}

// setupDirectoryWatch sets up watching for a directory
func (m *FileWatchModule) setupDirectoryWatch(dirPath string) error {
	// Check if directory exists
	if stat, err := os.Stat(dirPath); err != nil {
		return fmt.Errorf("directory %s does not exist: %v", dirPath, err)
	} else if !stat.IsDir() {
		return fmt.Errorf("%s is not a directory", dirPath)
	}

	return m.watchDirectory(dirPath)
}

// watchFile sets up watching for an existing file
func (m *FileWatchModule) watchFile(path string) error {
	m.watcherMutex.Lock()
	defer m.watcherMutex.Unlock()

	// Add to fsnotify watcher
	if err := m.watcher.Add(path); err != nil {
		return fmt.Errorf("failed to add file watcher for %s: %v", path, err)
	}

	// Get initial file info
	stat, err := os.Stat(path)
	if err != nil {
		m.logger.Warn("Failed to get initial file stats", "path", path, "error", err)
	}

	// Create file watcher
	fileWatcher := &FileWatcher{
		path:     path,
		exists:   true,
		lastStat: stat,
	}

	m.fileWatchers[path] = fileWatcher

	// Remove from directory watchers if present
	dir := filepath.Dir(path)
	filename := filepath.Base(path)
	if dirWatcher, exists := m.dirWatchers[dir]; exists && !dirWatcher.isTargetDir {
		delete(dirWatcher.targetFiles, filename)
		if len(dirWatcher.targetFiles) == 0 {
			// No more files to watch in this directory
			m.watcher.Remove(dir)
			delete(m.dirWatchers, dir)
		}
	}

	m.logger.Info("Started watching file", "path", path)
	return nil
}

// watchDirectoryForFile sets up watching for a directory (waiting for file creation)
func (m *FileWatchModule) watchDirectoryForFile(filePath string) error {
	m.watcherMutex.Lock()
	defer m.watcherMutex.Unlock()

	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("directory %s does not exist", dir)
	}

	// Get or create directory watcher
	dirWatcher, exists := m.dirWatchers[dir]
	if !exists {
		// Add directory to fsnotify watcher
		if err := m.watcher.Add(dir); err != nil {
			return fmt.Errorf("failed to add directory watcher for %s: %v", dir, err)
		}

		dirWatcher = &DirWatcher{
			path:        dir,
			isTargetDir: false,
			targetFiles: make(map[string]bool),
		}
		m.dirWatchers[dir] = dirWatcher
	}

	// Add file to directory watcher (only if not a target dir)
	if !dirWatcher.isTargetDir {
		dirWatcher.targetFiles[filename] = true
	}

	m.logger.Info("Started watching directory for file", "directory", dir, "file", filename)
	return nil
}

// watchDirectory sets up watching for a directory (monitoring contents)
func (m *FileWatchModule) watchDirectory(dirPath string) error {
	m.watcherMutex.Lock()
	defer m.watcherMutex.Unlock()

	// Add directory to fsnotify watcher
	if err := m.watcher.Add(dirPath); err != nil {
		return fmt.Errorf("failed to add directory watcher for %s: %v", dirPath, err)
	}

	// Get initial directory listing
	listing, err := m.getDirectoryListing(dirPath)
	if err != nil {
		m.logger.Warn("Failed to get initial directory listing", "path", dirPath, "error", err)
		listing = make(map[string]bool)
	}

	// Create directory watcher
	dirWatcher := &DirWatcher{
		path:        dirPath,
		isTargetDir: true,
		lastListing: listing,
	}

	m.dirWatchers[dirPath] = dirWatcher

	m.logger.Info("Started watching directory", "path", dirPath, "files_count", len(listing))
	return nil
}

// getDirectoryListing gets the current directory listing
func (m *FileWatchModule) getDirectoryListing(dirPath string) (map[string]bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, err
	}

	listing := make(map[string]bool)
	for _, entry := range entries {
		listing[entry.Name()] = true
	}

	return listing, nil
}

// monitorEvents monitors file system events
func (m *FileWatchModule) monitorEvents() {
	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.handleFSEvent(event)

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Error("File watcher error", "error", err)

		case <-m.stopChan:
			return
		}
	}
}

// handleFSEvent handles a file system event from fsnotify
func (m *FileWatchModule) handleFSEvent(event fsnotify.Event) {
	m.watcherMutex.RLock()
	defer m.watcherMutex.RUnlock()

	path := event.Name

	// Check if this is a watched file
	if fileWatcher, exists := m.fileWatchers[path]; exists {
		m.handleFileEvent(event, fileWatcher)
		return
	}

	// Check if this is in a watched directory
	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	if dirWatcher, exists := m.dirWatchers[dir]; exists {
		if dirWatcher.isTargetDir {
			// This is a target directory, handle directory event
			m.handleDirectoryEvent(event, dirWatcher)
		} else {
			// This is a directory we're watching for specific files
			if dirWatcher.targetFiles[filename] {
				m.handleFileCreationEvent(event)
			}
		}
	}
}

// handleFileEvent handles an event for a watched file
func (m *FileWatchModule) handleFileEvent(event fsnotify.Event, fileWatcher *FileWatcher) {
	eventType := m.mapFSEventType(event.Op)

	// Check if we should handle this event type using flags
	if !m.shouldHandleFileEvent(eventType) {
		return
	}

	// Handle file removal
	if event.Op&fsnotify.Remove == fsnotify.Remove {
		m.handleFileRemoval(fileWatcher)
	}

	// Create file event
	fileEvent := m.createFileEvent(eventType, event.Name, "")

	// Update last stat if file still exists
	if stat, err := os.Stat(event.Name); err == nil {
		fileWatcher.lastStat = stat
	}

	m.processFileEvent(fileEvent)
}

// handleDirectoryEvent handles an event in a watched directory
func (m *FileWatchModule) handleDirectoryEvent(event fsnotify.Event, dirWatcher *DirWatcher) {
	// Get current directory listing
	currentListing, err := m.getDirectoryListing(dirWatcher.path)
	if err != nil {
		m.logger.Error("Failed to get directory listing", "path", dirWatcher.path, "error", err)
		return
	}

	// Compare with last listing to detect changes
	added, removed := m.compareDirectoryListings(dirWatcher.lastListing, currentListing)

	// Generate events for added files
	if len(added) > 0 && m.eventFlags.DirAdd {
		for _, filename := range added {
			fullPath := filepath.Join(dirWatcher.path, filename)
			fileEvent := m.createFileEvent("dir_add", dirWatcher.path, fullPath)
			if m.config.IncludeList {
				fileEvent.DirListing = m.mapToSlice(currentListing)
			}
			m.processFileEvent(fileEvent)
		}
	}

	// Generate events for removed files
	if len(removed) > 0 && m.eventFlags.DirRemove {
		for _, filename := range removed {
			fullPath := filepath.Join(dirWatcher.path, filename)
			fileEvent := m.createFileEvent("dir_remove", dirWatcher.path, fullPath)
			if m.config.IncludeList {
				fileEvent.DirListing = m.mapToSlice(currentListing)
			}
			m.processFileEvent(fileEvent)
		}
	}

	// Generate general change event if anything changed
	if (len(added) > 0 || len(removed) > 0) && m.eventFlags.DirChange {
		fileEvent := m.createFileEvent("dir_change", dirWatcher.path, "")
		if m.config.IncludeList {
			fileEvent.DirListing = m.mapToSlice(currentListing)
		}
		m.processFileEvent(fileEvent)
	}

	// Update last listing
	dirWatcher.lastListing = currentListing
}

// handleFileCreationEvent handles file creation in a watched directory
func (m *FileWatchModule) handleFileCreationEvent(event fsnotify.Event) {
	// Only handle create events
	if event.Op&fsnotify.Create == fsnotify.Create {
		// File was created, switch to watching the file directly
		go func() {
			// Small delay to ensure file is fully created
			time.Sleep(100 * time.Millisecond)
			if err := m.watchFile(event.Name); err != nil {
				m.logger.Error("Failed to switch to file watching", "path", event.Name, "error", err)
			} else {
				// Generate create event
				if m.eventFlags.Create {
					fileEvent := m.createFileEvent("create", event.Name, "")
					m.processFileEvent(fileEvent)
				}
			}
		}()
	}
}

// handleFileRemoval handles file removal
func (m *FileWatchModule) handleFileRemoval(fileWatcher *FileWatcher) {
	m.watcherMutex.Lock()
	defer m.watcherMutex.Unlock()

	path := fileWatcher.path

	// Remove from file watchers
	delete(m.fileWatchers, path)

	// Switch back to directory watching
	go func() {
		time.Sleep(100 * time.Millisecond) // Small delay
		if err := m.watchDirectoryForFile(path); err != nil {
			m.logger.Error("Failed to switch to directory watching", "path", path, "error", err)
		}
	}()
}

// compareDirectoryListings compares two directory listings and returns added/removed files
func (m *FileWatchModule) compareDirectoryListings(old, new map[string]bool) (added, removed []string) {
	// Find added files
	for filename := range new {
		if !old[filename] {
			added = append(added, filename)
		}
	}

	// Find removed files
	for filename := range old {
		if !new[filename] {
			removed = append(removed, filename)
		}
	}

	return added, removed
}

// mapToSlice converts a map[string]bool to []string
func (m *FileWatchModule) mapToSlice(m2 map[string]bool) []string {
	result := make([]string, 0, len(m2))
	for key := range m2 {
		result = append(result, key)
	}
	return result
}

// mapFSEventType maps fsnotify event type to our event type
func (m *FileWatchModule) mapFSEventType(op fsnotify.Op) string {
	switch {
	case op&fsnotify.Create == fsnotify.Create:
		return "create"
	case op&fsnotify.Write == fsnotify.Write:
		return "write"
	case op&fsnotify.Remove == fsnotify.Remove:
		return "remove"
	case op&fsnotify.Rename == fsnotify.Rename:
		return "rename"
	case op&fsnotify.Chmod == fsnotify.Chmod:
		return "chmod"
	default:
		return "unknown"
	}
}

// shouldHandleFileEvent checks if we should handle this file event type using flags
func (m *FileWatchModule) shouldHandleFileEvent(eventType string) bool {
	switch eventType {
	case "create":
		return m.eventFlags.Create
	case "write":
		return m.eventFlags.Write
	case "remove":
		return m.eventFlags.Remove
	case "rename":
		return m.eventFlags.Rename
	case "chmod":
		return m.eventFlags.Chmod
	default:
		return false
	}
}

// createFileEvent creates a FileEvent from the given parameters
func (m *FileWatchModule) createFileEvent(eventType, path, targetPath string) *FileEvent {
	fileEvent := &FileEvent{
		Type:        eventType,
		Path:        path,
		TargetPath:  targetPath,
		Timestamp:   time.Now(),
		ModuleID:    m.id,
		IsDirectory: strings.HasPrefix(eventType, "dir_"),
	}

	// Get file info if file exists and it's not a directory event
	if !fileEvent.IsDirectory {
		if stat, err := os.Stat(path); err == nil {
			fileEvent.Size = stat.Size()
			fileEvent.Mode = stat.Mode()
		}

		// Read file content if requested and appropriate event
		if m.config.IncludeContent && (eventType == "create" || eventType == "write") {
			content, err := m.readFileContent(path)
			if err != nil {
				fileEvent.Error = fmt.Sprintf("Failed to read file content: %v", err)
				m.logger.Warn("Failed to read file content", "path", path, "error", err)
			} else {
				fileEvent.Content = content
			}
		}
	}

	return fileEvent
}

// readFileContent reads file content with size and timeout limits
func (m *FileWatchModule) readFileContent(path string) (string, error) {
	// Check file size
	stat, err := os.Stat(path)
	if err != nil {
		return "", err
	}

	if stat.Size() > m.config.MaxFileSize {
		return "", fmt.Errorf("file size %d exceeds maximum %d", stat.Size(), m.config.MaxFileSize)
	}

	// Read with timeout
	done := make(chan struct{})
	var content []byte
	var readErr error

	go func() {
		defer close(done)
		content, readErr = os.ReadFile(path)
	}()

	select {
	case <-done:
		if readErr != nil {
			return "", readErr
		}
		return string(content), nil
	case <-time.After(time.Duration(m.config.ReadTimeout) * time.Millisecond):
		return "", fmt.Errorf("read timeout after %dms", m.config.ReadTimeout)
	}
}

// processFileEvent processes a file event and executes triggers
func (m *FileWatchModule) processFileEvent(fileEvent *FileEvent) {
	m.logger.Info("File event detected",
		"type", fileEvent.Type,
		"path", fileEvent.Path,
		"target_path", fileEvent.TargetPath,
		"size", fileEvent.Size,
		"is_directory", fileEvent.IsDirectory,
		"has_content", fileEvent.Content != "",
		"has_listing", len(fileEvent.DirListing) > 0)

	// Prepare trigger arguments
	args := map[string]interface{}{
		"alert_type":      "file_event",
		"event_type":      fileEvent.Type,
		"path":            fileEvent.Path,
		"target_path":     fileEvent.TargetPath,
		"timestamp":       fileEvent.Timestamp,
		"size":            fileEvent.Size,
		"mode":            fileEvent.Mode.String(),
		"module_id":       fileEvent.ModuleID,
		"is_directory":    fileEvent.IsDirectory,
		"include_content": m.config.IncludeContent,
		"include_list":    m.config.IncludeList,
	}

	// Add content if available
	if fileEvent.Content != "" {
		args["content"] = fileEvent.Content
		args["content_length"] = len(fileEvent.Content)
	}

	// Add directory listing if available
	if len(fileEvent.DirListing) > 0 {
		args["dir_listing"] = fileEvent.DirListing
		args["dir_file_count"] = len(fileEvent.DirListing)
	}

	// Add error if present
	if fileEvent.Error != "" {
		args["error"] = fileEvent.Error
	}

	// Execute triggers
	for _, triggerID := range m.config.Triggers {
		if err := m.api.ExecuteTrigger(triggerID, args); err != nil {
			m.logger.Error("Failed to execute trigger",
				"trigger", triggerID, "path", fileEvent.Path, "error", err)
		}
	}
}
