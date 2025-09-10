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
	Interface        string   `toml:"interface"`
	Protocols        []string `toml:"protocols"`
	TimeWindow       int      `toml:"time_window"`
	MaxPings         int      `toml:"max_pings"`
	PortMode         string   `toml:"port_mode"`
	Ports            []int    `toml:"ports"`
	CleanupInterval  int      `toml:"cleanup_interval"`
	Triggers         []string `toml:"triggers"`
	DetectStealth    bool     `toml:"detect_stealth"`
	DetectFragmented bool     `toml:"detect_fragmented"`
	IgnoreOutbound   bool     `toml:"ignore_outbound"`
	QueueSize        int      `toml:"queue_size"`
	NumWorkers       int      `toml:"num_workers"`
}

// VerticalScanModule represents an instance of the vertical scan module
type VerticalScanModule struct {
	id             string
	config         VerticalScanConfig
	api            api.CoreAPI
	logger         api.Logger
	handle         *afpacket.TPacket
	tracker        *api.TimeWindowTracker[*ScanData]
	running        bool
	stopChan       chan struct{}
	waitGroup      sync.WaitGroup
	localNetworks  []net.IPNet
	connectionMap  sync.Map
	ipCacheTTL     time.Duration
	lastNetRefresh time.Time
}

// ScanData represents scanning activity data for the time window tracker
type ScanData struct {
	IP           string
	Ports        []int
	ScanTypes    []string
	TotalPings   int
	LastProtocol string
}

// ConnectionKey represents a connection identifier
type ConnectionKey struct {
	SrcIP   string
	DstIP   string
	DstPort int
	Proto   string
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
		Description: "Detects vertical port scans and stealth scans using AF_PACKET with  time window tracking",
		Version:     "3.0.0",
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

	if _, exists := configMap["id"]; !exists {
		return fmt.Errorf("verticalscan config must have an ID")
	}

	if _, exists := configMap["interface"]; !exists {
		return fmt.Errorf("verticalscan config must specify interface")
	}

	iface := fmt.Sprintf("%v", configMap["interface"])
	if _, err := net.InterfaceByName(iface); err != nil {
		return fmt.Errorf("network interface %s not found: %w", iface, err)
	}

	if mode, exists := configMap["port_mode"]; exists {
		modeStr := fmt.Sprintf("%v", mode)
		if modeStr != "whitelist" && modeStr != "blacklist" {
			return fmt.Errorf("port_mode must be 'whitelist' or 'blacklist'")
		}
	}

	if timeWindow, exists := configMap["time_window"]; exists {
		if tw, ok := timeWindow.(int64); ok && tw < 0 {
			return fmt.Errorf("time_window must be positive")
		}
	}

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
			Description: "Vertical port scan detection module with  time window tracking",
			ConfigType:  reflect.TypeOf(VerticalScanConfig{}),
			Factory:     p.createVerticalScanModule,
		},
	}
}

// RegisterTriggers returns the triggers provided by this plugin
func (p *VerticalScanPlugin) RegisterTriggers() []api.TriggerDefinition {
	return []api.TriggerDefinition{}
}

// createVerticalScanModule creates a new vertical scan module instance
func (p *VerticalScanPlugin) createVerticalScanModule(config interface{}) (api.ModuleInstance, error) {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid config format")
	}

	cfg := VerticalScanConfig{
		TimeWindow:       30,
		MaxPings:         10,
		PortMode:         "blacklist",
		Ports:            []int{},
		CleanupInterval:  60,
		DetectStealth:    true,
		DetectFragmented: true,
		IgnoreOutbound:   true,
		Protocols:        []string{"tcp", "udp"},
		QueueSize:        5000,
		NumWorkers:       2,
	}

	if err := p.parseConfig(configMap, &cfg); err != nil {
		return nil, err
	}

	if err := p.ValidateConfig(configMap); err != nil {
		return nil, err
	}

	module := &VerticalScanModule{
		id:         cfg.ID,
		config:     cfg,
		api:        p.api,
		logger:     p.api.GetLogger(fmt.Sprintf("verticalscan.%s", cfg.ID)),
		stopChan:   make(chan struct{}),
		ipCacheTTL: 5 * time.Minute,
	}

	trackerConfig := api.TimeWindowConfig{
		TimeWindow:      time.Duration(cfg.TimeWindow) * time.Second,
		MaxHits:         cfg.MaxPings,
		CleanupInterval: time.Duration(cfg.CleanupInterval) * time.Second,
		QueueSize:       cfg.QueueSize,
		NumWorkers:      cfg.NumWorkers,
	}

	module.tracker = api.NewTimeWindowTracker(
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

	if ignoreOutbound, exists := configMap["ignore_outbound"]; exists {
		if io, ok := ignoreOutbound.(bool); ok {
			cfg.IgnoreOutbound = io
		}
	}

	if queueSize, exists := configMap["queue_size"]; exists {
		if qs, ok := queueSize.(int64); ok {
			cfg.QueueSize = int(qs)
		}
	}

	if numWorkers, exists := configMap["num_workers"]; exists {
		if nw, ok := numWorkers.(int64); ok {
			cfg.NumWorkers = int(nw)
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
		"max_pings", m.config.MaxPings,
		"ignore_outbound", m.config.IgnoreOutbound)

	if err := m.refreshLocalNetworks(); err != nil {
		return fmt.Errorf("failed to get local networks: %w", err)
	}

	handle, err := afpacket.NewTPacket(afpacket.OptInterface(m.config.Interface))
	if err != nil {
		return fmt.Errorf("failed to create AF_PACKET socket: %w", err)
	}

	m.handle = handle
	m.running = true

	m.tracker.Start()

	m.waitGroup.Add(1)
	go m.capturePackets()

	go m.connectionCleanupLoop()

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
	return nil
}

// refreshLocalNetworks gets local network ranges
func (m *VerticalScanModule) refreshLocalNetworks() error {
	if time.Since(m.lastNetRefresh) < m.ipCacheTTL {
		return nil
	}

	iface, err := net.InterfaceByName(m.config.Interface)
	if err != nil {
		return err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}

	m.localNetworks = []net.IPNet{}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			m.localNetworks = append(m.localNetworks, *ipnet)
		}
	}

	m.lastNetRefresh = time.Now()
	return nil
}

// isLocalIP checks if an IP is in local networks
func (m *VerticalScanModule) isLocalIP(ip string) bool {
	if time.Since(m.lastNetRefresh) > m.ipCacheTTL {
		m.refreshLocalNetworks()
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return false
	}

	for _, network := range m.localNetworks {
		if network.Contains(targetIP) {
			return true
		}
	}

	return false
}

// isOutboundConnection checks if this is an outbound connection we initiated
func (m *VerticalScanModule) isOutboundConnection(srcIP, dstIP string, dstPort int, protocol string, tcp *layers.TCP) bool {
	if !m.config.IgnoreOutbound {
		return false
	}

	connKey := ConnectionKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		DstPort: dstPort,
		Proto:   protocol,
	}

	if protocol == "tcp" && tcp != nil {
		if tcp.SYN && !tcp.ACK {
			if m.isLocalIP(srcIP) && !m.isLocalIP(dstIP) {
				m.connectionMap.Store(connKey, time.Now())
				return true
			}
		}

		if _, exists := m.connectionMap.Load(connKey); exists {
			return true
		}
	}

	return false
}

// connectionCleanupLoop cleans old connection entries
func (m *VerticalScanModule) connectionCleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-10 * time.Minute)
			m.connectionMap.Range(func(key, value interface{}) bool {
				if timestamp, ok := value.(time.Time); ok && timestamp.Before(cutoff) {
					m.connectionMap.Delete(key)
				}
				return true
			})
		case <-m.stopChan:
			return
		}
	}
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
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	var srcIP, dstIP string
	var dstPort int
	var protocol string
	var scanType ScanType
	var isFragmented bool

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

	var tcp *layers.TCP
	if tcpLayer, ok := transportLayer.(*layers.TCP); ok {
		protocol = "tcp"
		tcp = tcpLayer
		if !m.shouldMonitorProtocol("tcp") {
			return
		}

		dstPort = int(tcp.DstPort)
		scanType = m.determineTCPScanType(tcp)

		if !m.isConnectionInitiation(tcp) {
			return
		}

	} else if udp, ok := transportLayer.(*layers.UDP); ok {
		protocol = "udp"
		if !m.shouldMonitorProtocol("udp") {
			return
		}

		dstPort = int(udp.DstPort)
		scanType = ScanTypeConnect

	} else {
		return
	}

	if !m.shouldMonitorPort(dstPort) {
		return
	}

	if !m.isLocalIP(dstIP) {
		return
	}

	if m.isOutboundConnection(srcIP, dstIP, dstPort, protocol, tcp) {
		return
	}

	m.trackScanAttempt(srcIP, dstPort, protocol, scanType, isFragmented)
}

// isConnectionInitiation checks if this packet represents a connection attempt
func (m *VerticalScanModule) isConnectionInitiation(tcp *layers.TCP) bool {
	return tcp.SYN && !tcp.ACK
}

// trackScanAttempt tracks a scan attempt using the  time window tracker
func (m *VerticalScanModule) trackScanAttempt(srcIP string, dstPort int, protocol string, scanType ScanType, isFragmented bool) {
	scanData := &ScanData{
		IP:           srcIP,
		Ports:        []int{dstPort},
		ScanTypes:    []string{m.getScanTypeName(scanType)},
		TotalPings:   1,
		LastProtocol: protocol,
	}

	if isFragmented && m.config.DetectFragmented {
		scanData.ScanTypes = append(scanData.ScanTypes, "fragmented")
	}

	metadata := map[string]interface{}{
		"port":          dstPort,
		"protocol":      protocol,
		"scan_type":     m.getScanTypeName(scanType),
		"is_fragmented": isFragmented,
		"timestamp":     time.Now(),
	}

	queued := m.tracker.Track(srcIP, scanData, metadata)
	if !queued {
		m.logger.Debug("Scan tracking event dropped due to full queue", "source_ip", srcIP)
	}
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

	args := map[string]interface{}{
		"scan_type":    "vertical",
		"source_ip":    scanData.IP,
		"protocol":     scanData.LastProtocol,
		"port_count":   len(scanData.Ports),
		"ports":        scanData.Ports,
		"scan_methods": scanData.ScanTypes,
		"total_hits":   entry.HitCount,
		"max_hits":     m.config.MaxPings,
		"first_seen":   entry.FirstSeen,
		"last_seen":    entry.LastSeen,
		"time_window":  m.config.TimeWindow,
		"severity":     m.calculateSeverity(scanData),
	}

	for _, triggerID := range m.config.Triggers {
		if err := m.api.ExecuteTrigger(triggerID, args); err != nil {
			m.logger.Error("Failed to execute trigger", "trigger", triggerID, "error", err)
		}
	}
}

// determineTCPScanType determines the type of TCP scan based on flags
func (m *VerticalScanModule) determineTCPScanType(tcp *layers.TCP) ScanType {
	if tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG {
		return ScanTypeSYN
	}

	if tcp.FIN && !tcp.SYN && !tcp.ACK && !tcp.RST && !tcp.PSH && !tcp.URG {
		return ScanTypeFIN
	}

	if tcp.FIN && tcp.PSH && tcp.URG && !tcp.SYN && !tcp.ACK && !tcp.RST {
		return ScanTypeXmas
	}

	if !tcp.FIN && !tcp.SYN && !tcp.ACK && !tcp.RST && !tcp.PSH && !tcp.URG {
		return ScanTypeNull
	}

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
	} else {
		return !inList
	}
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

// calculateSeverity calculates severity based on scan characteristics
func (m *VerticalScanModule) calculateSeverity(scanData *ScanData) string {
	for _, scanType := range scanData.ScanTypes {
		if scanType == "syn" || scanType == "fin" || scanType == "xmas" ||
			scanType == "null" || scanType == "fragmented" {
			return "high"
		}
	}

	if len(scanData.Ports) > 50 {
		return "medium"
	}

	return "low"
}
