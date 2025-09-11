package main

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sammwyy/spear/api"
)

// UserWatchPlugin is the main plugin struct
type UserWatchPlugin struct {
	api    api.CoreAPI
	logger api.Logger
}

// UserWatchConfig represents the configuration for a userwatch instance
type UserWatchConfig struct {
	ID                 string   `toml:"id"`
	WatchUsers         bool     `toml:"watch_users"`          // Watch user changes (default: true)
	WatchGroups        bool     `toml:"watch_groups"`         // Watch group changes (default: true)
	WatchPasswords     bool     `toml:"watch_passwords"`      // Watch password changes (default: true)
	UserMode           string   `toml:"user_mode"`            // "whitelist" or "blacklist" (default: "blacklist")
	UserList           []string `toml:"user_list"`            // List of users for whitelist/blacklist
	MinUID             int      `toml:"min_uid"`              // Minimum UID to monitor (default: 1000)
	MaxUID             int      `toml:"max_uid"`              // Maximum UID to monitor (default: 65533)
	IgnoreSystemUsers  bool     `toml:"ignore_system_users"`  // Ignore system users (default: true)
	PasswdFile         string   `toml:"passwd_file"`          // Path to passwd file (default: /etc/passwd)
	ShadowFile         string   `toml:"shadow_file"`          // Path to shadow file (default: /etc/shadow)
	GroupFile          string   `toml:"group_file"`           // Path to group file (default: /etc/group)
	CheckInterval      int      `toml:"check_interval"`       // Check interval in seconds (default: 5)
	Triggers           []string `toml:"triggers"`             // Triggers to execute
	IncludeFileContent bool     `toml:"include_file_content"` // Include file content in events (default: false)
}

// UserWatchModule represents an instance of the userwatch module
type UserWatchModule struct {
	id       string
	config   UserWatchConfig
	api      api.CoreAPI
	logger   api.Logger
	watcher  *fsnotify.Watcher
	stopChan chan bool

	// File state tracking
	lastPasswdState map[string]*UserEntry
	lastShadowState map[string]*ShadowEntry
	lastGroupState  map[string]*GroupEntry
}

// UserEntry represents a user entry from passwd file
type UserEntry struct {
	Username string
	UID      int
	GID      int
	Home     string
	Shell    string
	Gecos    string
}

// ShadowEntry represents a shadow entry from shadow file
type ShadowEntry struct {
	Username     string
	PasswordHash string // SHA256 of the actual hash for comparison
}

// GroupEntry represents a group entry from group file
type GroupEntry struct {
	GroupName string
	GID       int
	Members   []string
}

// UserChangeEvent represents a user change event
type UserChangeEvent struct {
	Type      string // "user_added", "user_removed", "user_modified", "password_changed", "group_added", "group_removed", "group_modified"
	Username  string
	GroupName string
	UID       int
	GID       int
	Changes   map[string]interface{} // Details of what changed
	Timestamp time.Time
	FileType  string // "passwd", "shadow", "group"
	OldValue  interface{}
	NewValue  interface{}
}

// NewPlugin creates a new userwatch plugin instance
func NewPlugin() api.Plugin {
	return &UserWatchPlugin{}
}

// Meta returns plugin metadata
func (p *UserWatchPlugin) Meta() api.PluginMeta {
	return api.PluginMeta{
		ID:          "userwatch",
		DisplayName: "User Account Watcher",
		Author:      "Spear Team",
		Repository:  "https://github.com/sammwyy/spear",
		Description: "Monitors system user accounts, groups, and password changes using inotify",
		Version:     "1.0.0",
	}
}

// Initialize initializes the plugin
func (p *UserWatchPlugin) Initialize(apiInstance api.CoreAPI) error {
	p.api = apiInstance
	p.logger = apiInstance.GetLogger("userwatch")
	p.logger.Info("UserWatch plugin initialized")
	return nil
}

// Shutdown shuts down the plugin
func (p *UserWatchPlugin) Shutdown() error {
	p.logger.Info("UserWatch plugin shutting down")
	return nil
}

// ValidateConfig validates the plugin configuration
func (p *UserWatchPlugin) ValidateConfig(config interface{}) error {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid config type for userwatch")
	}

	// Validate required fields
	if _, exists := configMap["id"]; !exists {
		return fmt.Errorf("userwatch config must have an ID")
	}

	// Validate user mode
	if userMode, exists := configMap["user_mode"]; exists {
		if mode, ok := userMode.(string); ok {
			if mode != "whitelist" && mode != "blacklist" {
				return fmt.Errorf("user_mode must be either 'whitelist' or 'blacklist'")
			}
		}
	}

	// Validate UID ranges
	if minUID, exists := configMap["min_uid"]; exists {
		if uid, ok := minUID.(int64); ok && uid < 0 {
			return fmt.Errorf("min_uid must be positive")
		}
	}

	if maxUID, exists := configMap["max_uid"]; exists {
		if uid, ok := maxUID.(int64); ok && uid < 0 {
			return fmt.Errorf("max_uid must be positive")
		}
	}

	// Validate check interval
	if checkInterval, exists := configMap["check_interval"]; exists {
		if ci, ok := checkInterval.(int64); ok && ci <= 0 {
			return fmt.Errorf("check_interval must be positive")
		}
	}

	return nil
}

// GetConfigSchema returns the configuration schema
func (p *UserWatchPlugin) GetConfigSchema() interface{} {
	return UserWatchConfig{}
}

// RegisterModules returns the modules provided by this plugin
func (p *UserWatchPlugin) RegisterModules() []api.ModuleDefinition {
	return []api.ModuleDefinition{
		{
			Name:        "userwatch",
			Description: "User account monitoring module with inotify file watching",
			ConfigType:  nil,
			Factory:     p.createUserWatchModule,
		},
	}
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *UserWatchPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{}
}

// createUserWatchModule creates a new userwatch module instance
func (p *UserWatchPlugin) createUserWatchModule(config interface{}) (api.ModuleInstance, error) {
	userConfig, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format")
	}

	// Parse config with defaults
	cfg := UserWatchConfig{
		WatchUsers:         true,
		WatchGroups:        true,
		WatchPasswords:     true,
		UserMode:           "blacklist",
		UserList:           []string{},
		MinUID:             1000,
		MaxUID:             65533,
		IgnoreSystemUsers:  true,
		PasswdFile:         "/etc/passwd",
		ShadowFile:         "/etc/shadow",
		GroupFile:          "/etc/group",
		CheckInterval:      5,
		Triggers:           []string{},
		IncludeFileContent: false,
	}

	if err := p.parseConfig(userConfig, &cfg); err != nil {
		return nil, err
	}

	// Validate config
	if err := p.ValidateConfig(userConfig); err != nil {
		return nil, err
	}

	module := &UserWatchModule{
		id:              cfg.ID,
		config:          cfg,
		api:             p.api,
		logger:          p.api.GetLogger(fmt.Sprintf("userwatch.%s", cfg.ID)),
		stopChan:        make(chan bool),
		lastPasswdState: make(map[string]*UserEntry),
		lastShadowState: make(map[string]*ShadowEntry),
		lastGroupState:  make(map[string]*GroupEntry),
	}

	return module, nil
}

// parseConfig parses configuration from map to struct
func (p *UserWatchPlugin) parseConfig(configMap map[string]interface{}, cfg *UserWatchConfig) error {
	if id, exists := configMap["id"]; exists {
		cfg.ID = fmt.Sprintf("%v", id)
	}

	if watchUsers, exists := configMap["watch_users"]; exists {
		if wu, ok := watchUsers.(bool); ok {
			cfg.WatchUsers = wu
		}
	}

	if watchGroups, exists := configMap["watch_groups"]; exists {
		if wg, ok := watchGroups.(bool); ok {
			cfg.WatchGroups = wg
		}
	}

	if watchPasswords, exists := configMap["watch_passwords"]; exists {
		if wp, ok := watchPasswords.(bool); ok {
			cfg.WatchPasswords = wp
		}
	}

	if userMode, exists := configMap["user_mode"]; exists {
		cfg.UserMode = fmt.Sprintf("%v", userMode)
	}

	if userList, exists := configMap["user_list"]; exists {
		if userSlice, ok := userList.([]interface{}); ok {
			cfg.UserList = []string{}
			for _, user := range userSlice {
				cfg.UserList = append(cfg.UserList, fmt.Sprintf("%v", user))
			}
		}
	}

	if minUID, exists := configMap["min_uid"]; exists {
		if uid, ok := minUID.(int64); ok {
			cfg.MinUID = int(uid)
		}
	}

	if maxUID, exists := configMap["max_uid"]; exists {
		if uid, ok := maxUID.(int64); ok {
			cfg.MaxUID = int(uid)
		}
	}

	if ignoreSystemUsers, exists := configMap["ignore_system_users"]; exists {
		if isu, ok := ignoreSystemUsers.(bool); ok {
			cfg.IgnoreSystemUsers = isu
		}
	}

	if passwdFile, exists := configMap["passwd_file"]; exists {
		cfg.PasswdFile = fmt.Sprintf("%v", passwdFile)
	}

	if shadowFile, exists := configMap["shadow_file"]; exists {
		cfg.ShadowFile = fmt.Sprintf("%v", shadowFile)
	}

	if groupFile, exists := configMap["group_file"]; exists {
		cfg.GroupFile = fmt.Sprintf("%v", groupFile)
	}

	if checkInterval, exists := configMap["check_interval"]; exists {
		if ci, ok := checkInterval.(int64); ok {
			cfg.CheckInterval = int(ci)
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

	if includeFileContent, exists := configMap["include_file_content"]; exists {
		if ifc, ok := includeFileContent.(bool); ok {
			cfg.IncludeFileContent = ifc
		}
	}

	return nil
}

// UserWatchModule methods

func (m *UserWatchModule) ID() string {
	return m.id
}

func (m *UserWatchModule) Start() error {
	m.logger.Info("Starting UserWatch module",
		"watch_users", m.config.WatchUsers,
		"watch_groups", m.config.WatchGroups,
		"watch_passwords", m.config.WatchPasswords,
		"user_mode", m.config.UserMode,
		"min_uid", m.config.MinUID,
		"max_uid", m.config.MaxUID)

	// Initialize file watcher
	var err error
	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}

	// Add files to watch
	filesToWatch := []string{}
	if m.config.WatchUsers {
		filesToWatch = append(filesToWatch, m.config.PasswdFile)
	}
	if m.config.WatchPasswords {
		filesToWatch = append(filesToWatch, m.config.ShadowFile)
	}
	if m.config.WatchGroups {
		filesToWatch = append(filesToWatch, m.config.GroupFile)
	}

	for _, file := range filesToWatch {
		if err := m.watcher.Add(file); err != nil {
			m.logger.Error("Failed to watch file", "file", file, "error", err)
		} else {
			m.logger.Info("Watching file", "file", file)
		}
	}

	// Load initial state
	if err := m.loadInitialState(); err != nil {
		m.logger.Error("Failed to load initial state", "error", err)
		return err
	}

	// Start monitoring goroutine
	go m.monitorFiles()

	return nil
}

func (m *UserWatchModule) Stop() error {
	m.logger.Info("Stopping UserWatch module")

	// Stop the monitoring goroutine
	close(m.stopChan)

	// Close file watcher
	if m.watcher != nil {
		m.watcher.Close()
	}

	return nil
}

func (m *UserWatchModule) HandleEvent(event api.Event) error {
	// This module doesn't handle external events
	return nil
}

// loadInitialState loads the initial state of all watched files
func (m *UserWatchModule) loadInitialState() error {
	if m.config.WatchUsers {
		if err := m.loadPasswdState(); err != nil {
			m.logger.Error("Failed to load passwd state", "error", err)
		}
	}

	if m.config.WatchPasswords {
		if err := m.loadShadowState(); err != nil {
			m.logger.Error("Failed to load shadow state", "error", err)
		}
	}

	if m.config.WatchGroups {
		if err := m.loadGroupState(); err != nil {
			m.logger.Error("Failed to load group state", "error", err)
		}
	}

	m.logger.Info("Initial state loaded successfully")
	return nil
}

// monitorFiles monitors file system events
func (m *UserWatchModule) monitorFiles() {
	ticker := time.NewTicker(time.Duration(m.config.CheckInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}

			if event.Op&fsnotify.Write == fsnotify.Write {
				m.logger.Debug("File modified", "file", event.Name)
				m.handleFileChange(event.Name)
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Error("File watcher error", "error", err)

		case <-ticker.C:
			// Periodic check for changes (fallback)
			m.checkAllFiles()

		case <-m.stopChan:
			return
		}
	}
}

// handleFileChange handles a file change event
func (m *UserWatchModule) handleFileChange(filename string) {
	switch filename {
	case m.config.PasswdFile:
		if m.config.WatchUsers {
			m.checkPasswdChanges()
		}
	case m.config.ShadowFile:
		if m.config.WatchPasswords {
			m.checkShadowChanges()
		}
	case m.config.GroupFile:
		if m.config.WatchGroups {
			m.checkGroupChanges()
		}
	}
}

// checkAllFiles checks all files for changes
func (m *UserWatchModule) checkAllFiles() {
	if m.config.WatchUsers {
		m.checkPasswdChanges()
	}
	if m.config.WatchPasswords {
		m.checkShadowChanges()
	}
	if m.config.WatchGroups {
		m.checkGroupChanges()
	}
}

// checkPasswdChanges checks for changes in passwd file
func (m *UserWatchModule) checkPasswdChanges() {
	newState, err := m.parsePasswdFile()
	if err != nil {
		m.logger.Error("Failed to parse passwd file", "error", err)
		return
	}

	// Compare with previous state
	m.comparePasswdState(newState)

	// Update state
	m.lastPasswdState = newState
}

// checkShadowChanges checks for changes in shadow file
func (m *UserWatchModule) checkShadowChanges() {
	newState, err := m.parseShadowFile()
	if err != nil {
		m.logger.Error("Failed to parse shadow file", "error", err)
		return
	}

	// Compare with previous state
	m.compareShadowState(newState)

	// Update state
	m.lastShadowState = newState
}

// checkGroupChanges checks for changes in group file
func (m *UserWatchModule) checkGroupChanges() {
	newState, err := m.parseGroupFile()
	if err != nil {
		m.logger.Error("Failed to parse group file", "error", err)
		return
	}

	// Compare with previous state
	m.compareGroupState(newState)

	// Update state
	m.lastGroupState = newState
}

// loadPasswdState loads the initial passwd state
func (m *UserWatchModule) loadPasswdState() error {
	state, err := m.parsePasswdFile()
	if err != nil {
		return err
	}
	m.lastPasswdState = state
	return nil
}

// loadShadowState loads the initial shadow state
func (m *UserWatchModule) loadShadowState() error {
	state, err := m.parseShadowFile()
	if err != nil {
		return err
	}
	m.lastShadowState = state
	return nil
}

// loadGroupState loads the initial group state
func (m *UserWatchModule) loadGroupState() error {
	state, err := m.parseGroupFile()
	if err != nil {
		return err
	}
	m.lastGroupState = state
	return nil
}

// parsePasswdFile parses the passwd file
func (m *UserWatchModule) parsePasswdFile() (map[string]*UserEntry, error) {
	file, err := os.Open(m.config.PasswdFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	state := make(map[string]*UserEntry)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		gid, err := strconv.Atoi(parts[3])
		if err != nil {
			continue
		}

		user := &UserEntry{
			Username: parts[0],
			UID:      uid,
			GID:      gid,
			Gecos:    parts[4],
			Home:     parts[5],
			Shell:    parts[6],
		}

		// Apply filters
		if m.shouldMonitorUser(user) {
			state[parts[0]] = user
		}
	}

	return state, scanner.Err()
}

// parseShadowFile parses the shadow file
func (m *UserWatchModule) parseShadowFile() (map[string]*ShadowEntry, error) {
	file, err := os.Open(m.config.ShadowFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	state := make(map[string]*ShadowEntry)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		// Hash the password hash for comparison
		hasher := sha256.New()
		hasher.Write([]byte(parts[1]))
		hashedPassword := fmt.Sprintf("%x", hasher.Sum(nil))

		shadow := &ShadowEntry{
			Username:     parts[0],
			PasswordHash: hashedPassword,
		}

		state[parts[0]] = shadow
	}

	return state, scanner.Err()
}

// parseGroupFile parses the group file
func (m *UserWatchModule) parseGroupFile() (map[string]*GroupEntry, error) {
	file, err := os.Open(m.config.GroupFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	state := make(map[string]*GroupEntry)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}

		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}

		members := []string{}
		if parts[3] != "" {
			members = strings.Split(parts[3], ",")
		}

		group := &GroupEntry{
			GroupName: parts[0],
			GID:       gid,
			Members:   members,
		}

		state[parts[0]] = group
	}

	return state, scanner.Err()
}

// comparePasswdState compares passwd states and generates events
func (m *UserWatchModule) comparePasswdState(newState map[string]*UserEntry) {
	// Check for new users
	for username, newUser := range newState {
		if oldUser, exists := m.lastPasswdState[username]; !exists {
			// User added
			m.generateUserEvent("user_added", username, newUser.UID, newUser.GID, map[string]interface{}{
				"home":  newUser.Home,
				"shell": newUser.Shell,
				"gecos": newUser.Gecos,
			}, nil, newUser)
		} else {
			// Check for modifications
			changes := m.compareUserEntries(oldUser, newUser)
			if len(changes) > 0 {
				m.generateUserEvent("user_modified", username, newUser.UID, newUser.GID, changes, oldUser, newUser)
			}
		}
	}

	// Check for removed users
	for username, oldUser := range m.lastPasswdState {
		if _, exists := newState[username]; !exists {
			m.generateUserEvent("user_removed", username, oldUser.UID, oldUser.GID, map[string]interface{}{
				"home":  oldUser.Home,
				"shell": oldUser.Shell,
				"gecos": oldUser.Gecos,
			}, oldUser, nil)
		}
	}
}

// compareShadowState compares shadow states and generates events
func (m *UserWatchModule) compareShadowState(newState map[string]*ShadowEntry) {
	for username, newShadow := range newState {
		if oldShadow, exists := m.lastShadowState[username]; exists {
			if oldShadow.PasswordHash != newShadow.PasswordHash {
				m.generateUserEvent("password_changed", username, 0, 0, map[string]interface{}{
					"password_changed": true,
				}, oldShadow, newShadow)
			}
		}
	}
}

// compareGroupState compares group states and generates events
func (m *UserWatchModule) compareGroupState(newState map[string]*GroupEntry) {
	// Check for new groups
	for groupName, newGroup := range newState {
		if oldGroup, exists := m.lastGroupState[groupName]; !exists {
			// Group added
			m.generateGroupEvent("group_added", groupName, newGroup.GID, map[string]interface{}{
				"members": newGroup.Members,
			}, nil, newGroup)
		} else {
			// Check for modifications
			changes := m.compareGroupEntries(oldGroup, newGroup)
			if len(changes) > 0 {
				m.generateGroupEvent("group_modified", groupName, newGroup.GID, changes, oldGroup, newGroup)
			}
		}
	}

	// Check for removed groups
	for groupName, oldGroup := range m.lastGroupState {
		if _, exists := newState[groupName]; !exists {
			m.generateGroupEvent("group_removed", groupName, oldGroup.GID, map[string]interface{}{
				"members": oldGroup.Members,
			}, oldGroup, nil)
		}
	}
}

// compareUserEntries compares two user entries and returns changes
func (m *UserWatchModule) compareUserEntries(old, new *UserEntry) map[string]interface{} {
	changes := make(map[string]interface{})

	if old.UID != new.UID {
		changes["uid"] = map[string]int{"old": old.UID, "new": new.UID}
	}
	if old.GID != new.GID {
		changes["gid"] = map[string]int{"old": old.GID, "new": new.GID}
	}
	if old.Home != new.Home {
		changes["home"] = map[string]string{"old": old.Home, "new": new.Home}
	}
	if old.Shell != new.Shell {
		changes["shell"] = map[string]string{"old": old.Shell, "new": new.Shell}
	}
	if old.Gecos != new.Gecos {
		changes["gecos"] = map[string]string{"old": old.Gecos, "new": new.Gecos}
	}

	return changes
}

// compareGroupEntries compares two group entries and returns changes
func (m *UserWatchModule) compareGroupEntries(old, new *GroupEntry) map[string]interface{} {
	changes := make(map[string]interface{})

	if old.GID != new.GID {
		changes["gid"] = map[string]int{"old": old.GID, "new": new.GID}
	}

	// Compare members
	if !m.equalStringSlices(old.Members, new.Members) {
		changes["members"] = map[string][]string{"old": old.Members, "new": new.Members}

		// Find added and removed members
		added := m.findAddedMembers(old.Members, new.Members)
		removed := m.findRemovedMembers(old.Members, new.Members)

		if len(added) > 0 {
			changes["members_added"] = added
		}
		if len(removed) > 0 {
			changes["members_removed"] = removed
		}
	}

	return changes
}

// generateUserEvent generates a user change event
func (m *UserWatchModule) generateUserEvent(eventType, username string, uid, gid int, changes map[string]interface{}, oldValue, newValue interface{}) {
	// Check if user should be monitored
	if !m.shouldMonitorUsername(username) {
		return
	}

	event := &UserChangeEvent{
		Type:      eventType,
		Username:  username,
		UID:       uid,
		GID:       gid,
		Changes:   changes,
		Timestamp: time.Now(),
		FileType:  "passwd",
		OldValue:  oldValue,
		NewValue:  newValue,
	}

	m.logger.Info("User change detected",
		"type", eventType,
		"username", username,
		"uid", uid,
		"gid", gid,
		"changes", changes)

	m.executeTriggersForEvent(event)
}

// generateGroupEvent generates a group change event
func (m *UserWatchModule) generateGroupEvent(eventType, groupName string, gid int, changes map[string]interface{}, oldValue, newValue interface{}) {
	event := &UserChangeEvent{
		Type:      eventType,
		GroupName: groupName,
		GID:       gid,
		Changes:   changes,
		Timestamp: time.Now(),
		FileType:  "group",
		OldValue:  oldValue,
		NewValue:  newValue,
	}

	m.logger.Info("Group change detected",
		"type", eventType,
		"group", groupName,
		"gid", gid,
		"changes", changes)

	m.executeTriggersForEvent(event)
}

// executeTriggersForEvent executes configured triggers for an event
func (m *UserWatchModule) executeTriggersForEvent(event *UserChangeEvent) {
	args := map[string]interface{}{
		"alert_type":  "user_change",
		"change_type": event.Type,
		"username":    event.Username,
		"group_name":  event.GroupName,
		"uid":         event.UID,
		"gid":         event.GID,
		"changes":     event.Changes,
		"timestamp":   event.Timestamp,
		"file_type":   event.FileType,
		"module_id":   m.id,
	}

	// Add file content if requested
	if m.config.IncludeFileContent {
		switch event.FileType {
		case "passwd":
			args["passwd_content"] = m.readFileContent(m.config.PasswdFile)
		case "shadow":
			args["shadow_content"] = m.readFileContent(m.config.ShadowFile)
		case "group":
			args["group_content"] = m.readFileContent(m.config.GroupFile)
		}
	}

	// Execute triggers
	for _, triggerID := range m.config.Triggers {
		if err := m.api.ExecuteTrigger(triggerID, args); err != nil {
			m.logger.Error("Failed to execute trigger",
				"trigger", triggerID, "error", err)
		}
	}
}

// shouldMonitorUser checks if a user should be monitored based on configuration
func (m *UserWatchModule) shouldMonitorUser(user *UserEntry) bool {
	// Check UID range
	if user.UID < m.config.MinUID || user.UID > m.config.MaxUID {
		return false
	}

	// Check system users
	if m.config.IgnoreSystemUsers && user.UID < 1000 {
		return false
	}

	return m.shouldMonitorUsername(user.Username)
}

// shouldMonitorUsername checks if a username should be monitored
func (m *UserWatchModule) shouldMonitorUsername(username string) bool {
	if len(m.config.UserList) == 0 {
		return true // No filter list, monitor all
	}

	inList := m.contains(m.config.UserList, username)

	if m.config.UserMode == "whitelist" {
		return inList
	} else { // blacklist
		return !inList
	}
}

// Helper functions

func (m *UserWatchModule) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (m *UserWatchModule) equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (m *UserWatchModule) findAddedMembers(old, new []string) []string {
	var added []string
	for _, newMember := range new {
		if !m.contains(old, newMember) {
			added = append(added, newMember)
		}
	}
	return added
}

func (m *UserWatchModule) findRemovedMembers(old, new []string) []string {
	var removed []string
	for _, oldMember := range old {
		if !m.contains(new, oldMember) {
			removed = append(removed, oldMember)
		}
	}
	return removed
}

func (m *UserWatchModule) readFileContent(filename string) string {
	content, err := os.ReadFile(filename)
	if err != nil {
		m.logger.Error("Failed to read file content", "file", filename, "error", err)
		return ""
	}
	return string(content)
}
