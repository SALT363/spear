package main

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/sammwyy/spear/api"
)

// VerticalScanPlugin is the main plugin struct
type VerticalScanPlugin struct {
	api    api.CoreAPI
	logger api.Logger
}

// VerticalScanConfig represents the configuration for the vertical scan module
type VerticalScanConfig struct {
	ID               string   `toml:"id"`
	Interface        string   `toml:"interface"`         // Network interface to monitor
	Protocols        []string `toml:"protocols"`         // tcp, udp
	TimeWindow       int      `toml:"time_window"`       // Time window in seconds
	MaxPings         int      `toml:"max_pings"`         // Maximum pings before triggering
	PortMode         string   `toml:"port_mode"`         // "whitelist" or "blacklist"
	Ports            []int    `toml:"ports"`             // List of ports
	CleanupInterval  int      `toml:"cleanup_interval"`  // Cleanup interval in seconds
	Triggers         []string `toml:"triggers"`          // Triggers to execute
	DetectStealth    bool     `toml:"detect_stealth"`    // Detect stealth scans
	DetectFragmented bool     `toml:"detect_fragmented"` // Detect fragmented packets
}

// VerticalScanModule represents an instance of the vertical scan module
type VerticalScanModule struct {
	id        string
	config    VerticalScanConfig
	api       api.CoreAPI
	logger    api.Logger
	handle    *afpacket.TPacket
	tracker   *api.TimeWindowTracker[*ScanData]
	running   bool
	stopChan  chan struct{}
	waitGroup sync.WaitGroup
}

// ScanData represents scanning activity data for the time window tracker
type ScanData struct {
	IP           string
	Ports        map[int]bool
	ScanTypes    map[string]bool // syn, fin, xmas, null, fragmented
	TCPFlags     []uint8         // History of TCP flags seen
	TotalPings   int
	LastProtocol string
}

// ScanType represents different types of scans
type ScanType int

const (
	ScanTypeSYN ScanType = iota
	ScanTypeFIN
	ScanTypeXmas
	ScanTypeNull
	ScanTypeConnect
	ScanTypeFragmented
)

// NewPlugin creates a new vertical scan plugin instance
func NewPlugin() api.Plugin {
	return &VerticalScanPlugin{}
}

// Meta returns plugin metadata
func (p *VerticalScanPlugin) Meta() api.PluginMeta {
	return api.PluginMeta{
		ID:          "verticalscan",
		DisplayName: "Vertical Port Scan Detector",
		Author:      "Spear Team",
		Repository:  "https://github.com/sammwyy/spear",
		Description: "Detects vertical port scans and stealth scans using AF_PACKET with time window tracking",
		Version:     "2.0.0",
	}
}

// Initialize initializes the plugin
func (p *VerticalScanPlugin) Initialize(apiInstance api.CoreAPI) error {
	p.api = apiInstance
	p.logger = apiInstance.GetLogger("verticalscan")
	p.logger.Info("VerticalScan plugin initialized")
	return nil
}

// Shutdown shuts down the plugin
func (p *VerticalScanPlugin) Shutdown() error {
	p.logger.Info("VerticalScan plugin shutting down")
	return nil
}

// ValidateConfig validates the plugin configuration
func (p *VerticalScanPlugin) ValidateConfig(config interface{}) error {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid config type for verticalscan")
	}

	// Validate required fields
	if _, exists := configMap["id"]; !exists {
		return fmt.Errorf("verticalscan config must have an ID")
	}

	if _, exists := configMap["interface"]; !exists {
		return fmt.Errorf("verticalscan config must specify interface")
	}

	// Validate interface exists
	iface := fmt.Sprintf("%v", configMap["interface"])
	if _, err := net.InterfaceByName(iface); err != nil {
		return fmt.Errorf("network interface %s not found: %w", iface, err)
	}

	// Validate port mode
	if mode, exists := configMap["port_mode"]; exists {
		modeStr := fmt.Sprintf("%v", mode)
		if modeStr != "whitelist" && modeStr != "blacklist" {
			return fmt.Errorf("port_mode must be 'whitelist' or 'blacklist'")
		}
	}

	// Validate time window
	if timeWindow, exists := configMap["time_window"]; exists {
		if tw, ok := timeWindow.(int64); ok && tw < 0 {
			return fmt.Errorf("time_window must be positive")
		}
	}

	// Validate max pings
	if maxPings, exists := configMap["max_pings"]; exists {
		if mp, ok := maxPings.(int64); ok && mp <= 0 {
			return fmt.Errorf("max_pings must be positive")
		}
	}

	return nil
}

// GetConfigSchema returns the configuration schema
func (p *VerticalScanPlugin) GetConfigSchema() interface{} {
	return VerticalScanConfig{}
}

// RegisterModules returns the modules provided by this plugin
func (p *VerticalScanPlugin) RegisterModules() []api.ModuleDefinition {
	return []api.ModuleDefinition{
		{
			Name:        "verticalscan",
			Description: "Vertical port scan detection module with time window tracking",
			ConfigType:  reflect.TypeOf(VerticalScanConfig{}),
			Factory:     p.createVerticalScanModule,
		},
	}
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *VerticalScanPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{} // This plugin doesn't provide triggers
}

// createVerticalScanModule creates a new vertical scan module instance
func (p *VerticalScanPlugin) createVerticalScanModule(config interface{}) (api.ModuleInstance, error) {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format")
	}

	// Parse configuration with defaults
	cfg := VerticalScanConfig{
		TimeWindow:       30,          // Default 30 seconds
		MaxPings:         10,          // Default 10 pings
		PortMode:         "blacklist", // Default blacklist (all ports)
		Ports:            []int{},     // Empty list
		CleanupInterval:  60,          // Default 60 seconds cleanup
		DetectStealth:    true,
		DetectFragmented: true,
		Protocols:        []string{"tcp", "udp"},
	}

	// Parse all configuration fields
	if err := p.parseConfig(configMap, &cfg); err != nil {
		return nil, err
	}

	// Validate config
	if err := p.ValidateConfig(configMap); err != nil {
		return nil, err
	}

	module := &VerticalScanModule{
		id:       cfg.ID,
		config:   cfg,
		api:      p.api,
		logger:   p.api.GetLogger(fmt.Sprintf("verticalscan.%s", cfg.ID)),
		stopChan: make(chan struct{}),
	}

	// Initialize time window tracker
	trackerConfig := api.TimeWindowConfig{
		TimeWindow:      time.Duration(cfg.TimeWindow) * time.Second,
		MaxHits:         cfg.MaxPings,
		CleanupInterval: time.Duration(cfg.CleanupInterval) * time.Second,
	}

	module.tracker = api.NewTimeWindowTracker[*ScanData](
		trackerConfig,
		module.onThresholdReached,
		module.logger,
	)

	return module, nil
}

// parseConfig parses configuration from map to struct
func (p *VerticalScanPlugin) parseConfig(configMap map[string]interface{}, cfg *VerticalScanConfig) error {
	if id, exists := configMap["id"]; exists {
		cfg.ID = fmt.Sprintf("%v", id)
	}

	if iface, exists := configMap["interface"]; exists {
		cfg.Interface = fmt.Sprintf("%v", iface)
	}

	if protocols, exists := configMap["protocols"]; exists {
		if protocolSlice, ok := protocols.([]interface{}); ok {
			cfg.Protocols = []string{}
			for _, proto := range protocolSlice {
				cfg.Protocols = append(cfg.Protocols, fmt.Sprintf("%v", proto))
			}
		}
	}

	if timeWindow, exists := configMap["time_window"]; exists {
		if tw, ok := timeWindow.(int64); ok {
			cfg.TimeWindow = int(tw)
		}
	}

	if maxPings, exists := configMap["max_pings"]; exists {
		if mp, ok := maxPings.(int64); ok {
			cfg.MaxPings = int(mp)
		}
	}

	if portMode, exists := configMap["port_mode"]; exists {
		cfg.PortMode = fmt.Sprintf("%v", portMode)
	}

	if ports, exists := configMap["ports"]; exists {
		if portSlice, ok := ports.([]interface{}); ok {
			cfg.Ports = []int{}
			for _, port := range portSlice {
				if p, ok := port.(int64); ok {
					cfg.Ports = append(cfg.Ports, int(p))
				}
			}
		}
	}

	if cleanupInterval, exists := configMap["cleanup_interval"]; exists {
		if ci, ok := cleanupInterval.(int64); ok {
			cfg.CleanupInterval = int(ci)
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

	if detectStealth, exists := configMap["detect_stealth"]; exists {
		if ds, ok := detectStealth.(bool); ok {
			cfg.DetectStealth = ds
		}
	}

	if detectFragmented, exists := configMap["detect_fragmented"]; exists {
		if df, ok := detectFragmented.(bool); ok {
			cfg.DetectFragmented = df
		}
	}

	return nil
}

// VerticalScanModule methods

func (m *VerticalScanModule) ID() string {
	return m.id
}

func (m *VerticalScanModule) Start() error {
	m.logger.Info("Starting VerticalScan module",
		"interface", m.config.Interface,
		"time_window", m.config.TimeWindow,
		"max_pings", m.config.MaxPings)

	// Create AF_PACKET socket
	handle, err := afpacket.NewTPacket(afpacket.OptInterface(m.config.Interface))
	if err != nil {
		return fmt.Errorf("failed to create AF_PACKET socket: %w", err)
	}

	m.handle = handle
	m.running = true

	// Start time window tracker
	m.tracker.Start()

	// Start packet capture goroutine
	m.waitGroup.Add(1)
	go m.capturePackets()

	m.logger.Info("VerticalScan module started")
	return nil
}

func (m *VerticalScanModule) Stop() error {
	m.logger.Info("Stopping VerticalScan module")

	m.running = false
	close(m.stopChan)

	if m.handle != nil {
		m.handle.Close()
	}

	if m.tracker != nil {
		m.tracker.Stop()
	}

	m.waitGroup.Wait()
	m.logger.Info("VerticalScan module stopped")
	return nil
}

func (m *VerticalScanModule) HandleEvent(event api.Event) error {
	// This module generates events, doesn't handle them
	return nil
}

// capturePackets captures and analyzes network packets
func (m *VerticalScanModule) capturePackets() {
	defer m.waitGroup.Done()

	packetSource := gopacket.NewPacketSource(m.handle, layers.LayerTypeEthernet)
	packetChan := packetSource.Packets()

	for {
		select {
		case <-m.stopChan:
			return
		case packet := <-packetChan:
			if packet == nil {
				continue
			}
			m.analyzePacket(packet)
		}
	}
}

// analyzePacket analyzes a single packet for scan patterns
func (m *VerticalScanModule) analyzePacket(packet gopacket.Packet) {
	// Get network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Get transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	var srcIP, dstIP string
	var dstPort int
	var protocol string
	var scanType ScanType
	var tcpFlags uint8
	var isFragmented bool

	// Parse IP layer
	if ipv4, ok := networkLayer.(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
		isFragmented = ipv4.Flags&layers.IPv4MoreFragments != 0 || ipv4.FragOffset != 0
	} else if ipv6, ok := networkLayer.(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	} else {
		return
	}

	// Check if we should monitor this protocol
	if tcp, ok := transportLayer.(*layers.TCP); ok {
		protocol = "tcp"
		if !m.shouldMonitorProtocol("tcp") {
			return
		}

		dstPort = int(tcp.DstPort)
		tcpFlags = tcpFlagsToByte(tcp)

		// Determine scan type based on TCP flags
		scanType = m.determineTCPScanType(tcp)

	} else if udp, ok := transportLayer.(*layers.UDP); ok {
		protocol = "udp"
		if !m.shouldMonitorProtocol("udp") {
			return
		}

		dstPort = int(udp.DstPort)
		scanType = ScanTypeConnect // UDP scans are typically connect-style

	} else {
		return
	}

	// Check if we should monitor this port
	if !m.shouldMonitorPort(dstPort) {
		return
	}

	// Check if this is a local destination (being scanned)
	if !m.isLocalIP(dstIP) {
		return
	}

	// Track the scan attempt
	m.trackScanAttempt(srcIP, dstPort, protocol, scanType, tcpFlags, isFragmented)
}

// trackScanAttempt tracks a scan attempt using the time window tracker
func (m *VerticalScanModule) trackScanAttempt(srcIP string, dstPort int, protocol string, scanType ScanType, tcpFlags uint8, isFragmented bool) {
	// Create tracking key (IP-based tracking)
	trackingKey := srcIP

	// Get existing data or create new
	var scanData *ScanData
	if entry, exists := m.tracker.Get(trackingKey); exists {
		scanData = entry.Data
	} else {
		scanData = &ScanData{
			IP:        srcIP,
			Ports:     make(map[int]bool),
			ScanTypes: make(map[string]bool),
			TCPFlags:  []uint8{},
		}
	}

	// Update scan data
	scanData.LastProtocol = protocol
	scanData.TCPFlags = append(scanData.TCPFlags, tcpFlags)

	// Track port if not seen before in this window
	if !scanData.Ports[dstPort] {
		scanData.Ports[dstPort] = true
		scanData.TotalPings++
	}

	// Track scan types
	scanTypeName := m.getScanTypeName(scanType)
	scanData.ScanTypes[scanTypeName] = true

	if isFragmented && m.config.DetectFragmented {
		scanData.ScanTypes["fragmented"] = true
	}

	// Create metadata for the tracker
	metadata := map[string]interface{}{
		"port":          dstPort,
		"protocol":      protocol,
		"scan_type":     scanTypeName,
		"tcp_flags":     tcpFlags,
		"is_fragmented": isFragmented,
		"timestamp":     time.Now(),
		"ports_scanned": len(scanData.Ports),
		"scan_methods":  m.getScanTypesList(scanData.ScanTypes),
		"total_pings":   scanData.TotalPings,
	}

	m.logger.Debug("Tracking scan attempt",
		"source_ip", srcIP,
		"port", dstPort,
		"protocol", protocol,
		"scan_type", scanTypeName,
		"ports_count", len(scanData.Ports))

	// Track the event - the tracker will handle threshold checking
	m.tracker.Track(trackingKey, scanData, metadata)
}

// onThresholdReached is called when the scan threshold is reached
func (m *VerticalScanModule) onThresholdReached(key string, entry *api.TimeWindowEntry[*ScanData]) {
	scanData := entry.Data

	m.logger.Warn("Vertical port scan detected",
		"source_ip", scanData.IP,
		"ports_scanned", len(scanData.Ports),
		"total_hits", entry.HitCount,
		"scan_types", scanData.ScanTypes,
		"protocol", scanData.LastProtocol,
		"time_window", m.config.TimeWindow,
		"severity", m.calculateSeverity(scanData))

	// Prepare trigger arguments
	args := map[string]interface{}{
		"scan_type":    "vertical",
		"source_ip":    scanData.IP,
		"protocol":     scanData.LastProtocol,
		"port_count":   len(scanData.Ports),
		"ports":        m.getPortList(scanData.Ports),
		"scan_methods": m.getScanTypesList(scanData.ScanTypes),
		"total_hits":   entry.HitCount,
		"max_hits":     m.config.MaxPings,
		"first_seen":   entry.FirstSeen,
		"last_seen":    entry.LastSeen,
		"time_window":  m.config.TimeWindow,
		"severity":     m.calculateSeverity(scanData),
		"tcp_flags":    scanData.TCPFlags,
		"metadata":     entry.Metadata,
	}

	// Execute configured triggers
	for _, triggerID := range m.config.Triggers {
		if err := m.api.ExecuteTrigger(triggerID, args); err != nil {
			m.logger.Error("Failed to execute trigger", "trigger", triggerID, "error", err)
		}
	}
}

func tcpFlagsToByte(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.FIN {
		flags |= 1 << 0
	}
	if tcp.SYN {
		flags |= 1 << 1
	}
	if tcp.RST {
		flags |= 1 << 2
	}
	if tcp.PSH {
		flags |= 1 << 3
	}
	if tcp.ACK {
		flags |= 1 << 4
	}
	if tcp.URG {
		flags |= 1 << 5
	}
	return flags
}

// determineTCPScanType determines the type of TCP scan based on flags
func (m *VerticalScanModule) determineTCPScanType(tcp *layers.TCP) ScanType {
	// SYN scan (only SYN flag set)
	if tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG {
		return ScanTypeSYN
	}

	// FIN scan (only FIN flag set)
	if tcp.FIN && !tcp.SYN && !tcp.ACK && !tcp.RST && !tcp.PSH && !tcp.URG {
		return ScanTypeFIN
	}

	// Xmas scan (FIN, PSH, URG flags set)
	if tcp.FIN && tcp.PSH && tcp.URG && !tcp.SYN && !tcp.ACK && !tcp.RST {
		return ScanTypeXmas
	}

	// Null scan (no flags set)
	if !tcp.FIN && !tcp.SYN && !tcp.ACK && !tcp.RST && !tcp.PSH && !tcp.URG {
		return ScanTypeNull
	}

	// Default to connect scan
	return ScanTypeConnect
}

// shouldMonitorProtocol checks if we should monitor this protocol
func (m *VerticalScanModule) shouldMonitorProtocol(protocol string) bool {
	for _, p := range m.config.Protocols {
		if p == protocol {
			return true
		}
	}
	return false
}

// shouldMonitorPort checks if we should monitor this port based on whitelist/blacklist
func (m *VerticalScanModule) shouldMonitorPort(port int) bool {
	if len(m.config.Ports) == 0 {
		// Empty list with blacklist means monitor all ports
		return m.config.PortMode == "blacklist"
	}

	inList := false
	for _, p := range m.config.Ports {
		if p == port {
			inList = true
			break
		}
	}

	if m.config.PortMode == "whitelist" {
		return inList
	} else { // blacklist
		return !inList
	}
}

// isLocalIP checks if an IP is local to this machine
func (m *VerticalScanModule) isLocalIP(ip string) bool {
	// Get interface
	iface, err := net.InterfaceByName(m.config.Interface)
	if err != nil {
		return false
	}

	// Get addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}

	targetIP := net.ParseIP(ip)

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.Equal(targetIP) {
				return true
			}
		}
	}

	return false
}

// getScanTypeName converts scan type to string
func (m *VerticalScanModule) getScanTypeName(scanType ScanType) string {
	switch scanType {
	case ScanTypeSYN:
		return "syn"
	case ScanTypeFIN:
		return "fin"
	case ScanTypeXmas:
		return "xmas"
	case ScanTypeNull:
		return "null"
	case ScanTypeFragmented:
		return "fragmented"
	default:
		return "connect"
	}
}

// getPortList converts port map to list
func (m *VerticalScanModule) getPortList(ports map[int]bool) []int {
	portList := make([]int, 0, len(ports))
	for port := range ports {
		portList = append(portList, port)
	}
	return portList
}

// getScanTypesList converts scan types map to list
func (m *VerticalScanModule) getScanTypesList(scanTypes map[string]bool) []string {
	typeList := make([]string, 0, len(scanTypes))
	for scanType := range scanTypes {
		typeList = append(typeList, scanType)
	}
	return typeList
}

// calculateSeverity calculates severity based on scan characteristics
func (m *VerticalScanModule) calculateSeverity(scanData *ScanData) string {
	// High severity for stealth scans
	if scanData.ScanTypes["syn"] || scanData.ScanTypes["fin"] ||
		scanData.ScanTypes["xmas"] || scanData.ScanTypes["null"] ||
		scanData.ScanTypes["fragmented"] {
		return "high"
	}

	// Medium severity for many ports
	if len(scanData.Ports) > 50 {
		return "medium"
	}

	return "low"
}
