package internal

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// == Analysis

const defaultMaxDestinations = 1024

type AnalysisConfiguration struct {
	// configuration
	PacketRateThreshold      float64
	DestinationRateThreshold float64
	Window                   time.Duration
	scanDetectionMode        ScanDetectionMode
	maxDestinations          int // maximum number of destinations to analyze per window

	// extra logging options
	showIdle    bool // emit idle windows when requested
	savePackets int  // number of packets to save, 0 means no packets are saved
	captureDir  string
	linkType    layers.LinkType

	// instance references
	eventFile   *os.File
	logger      *slog.Logger
	eventLogger *EveLogger

	result            batchResult
	buffers           map[string]*packetRing
	ignoredIP         map[string]struct{}
	summary           AnalysisSummary
	captureBehavior   func(*AnalysisConfiguration, *Behavior) (bool, error)
	previousScanHosts []Destination

	// static context for logging
	context AnalysisContext
}

type AnalysisSummary struct {
	AttackEvents  int
	ScanEvents    int
	IdleEvents    int
	SavedCaptures int
}

func (s AnalysisSummary) TotalAlerts() int {
	return s.AttackEvents + s.ScanEvents
}

type ScanDetectionMode uint8

const (
	ScanDetectionFilteredHostRate ScanDetectionMode = iota
	ScanDetectionHostRate
	ScanDetectionNewHostRate
)

const (
	scanDetectionFilteredHostRateLabel = "filtered-host-rate"
	scanDetectionHostRateLabel         = "host-rate"
	scanDetectionNewHostRateLabel      = "new-host-rate"
)

func (mode ScanDetectionMode) String() string {
	switch mode {
	case ScanDetectionHostRate:
		return scanDetectionHostRateLabel
	case ScanDetectionNewHostRate:
		return scanDetectionNewHostRateLabel
	default:
		return scanDetectionFilteredHostRateLabel
	}
}

func ParseScanDetectionMode(value string) (ScanDetectionMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", scanDetectionFilteredHostRateLabel:
		return ScanDetectionFilteredHostRate, nil
	case scanDetectionHostRateLabel:
		return ScanDetectionHostRate, nil
	case scanDetectionNewHostRateLabel:
		return ScanDetectionNewHostRate, nil
	default:
		return ScanDetectionFilteredHostRate, fmt.Errorf(
			"unsupported scan-detection-mode %q (expected %q, %q, or %q)",
			value,
			scanDetectionHostRateLabel,
			scanDetectionNewHostRateLabel,
			scanDetectionFilteredHostRateLabel,
		)
	}
}

type batchResult struct {
	windowStart             time.Time
	destinationPacketCounts destinationCounts
	globalPacketCount       int
}

type AnalysisContext struct {
	// instance configuration
	srcIP            string
	c2IP             string
	sampleID         string   // unique identifier to match behavior to a malware sample
	uninterestingIPs []string // List of IP addresses that are not interesting for analysis
}

func NewAnalysisConfiguration(
	srcIP string,
	c2IP string,
	filterIPs []string,
	showIdle bool,
	window time.Duration,
	filePath string,
	PacketThreshold float64,
	destinationThreshold float64,
	scanDetectionMode ScanDetectionMode,
	level slog.Level,
	sampleID string,
	savePackets int,
	captureDir string,
	captureBehavior func(*AnalysisConfiguration, *Behavior) (bool, error),
) *AnalysisConfiguration {
	var (
		file        *os.File
		eventWriter io.Writer = os.Stdout
	)

	if filePath != "" {
		var err error
		file, err = os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		eventWriter = file
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	eventLogger := NewEveLogger(eventWriter)

	if window <= 0 {
		panic("window duration must be greater than zero")
	}

	// source and C2 IPs should be excluded from analysis
	filterIPs = append(filterIPs, srcIP, c2IP)

	ignored := make(map[string]struct{}, len(filterIPs))
	for _, ip := range filterIPs {
		if ip == "" {
			continue
		}
		ignored[ip] = struct{}{}
	}

	var buffers map[string]*packetRing
	if savePackets > 0 {
		buffers = make(map[string]*packetRing)
	}

	if captureDir == "" {
		captureDir = filepath.Join(".", "captures")
	}
	captureDir = filepath.Clean(captureDir)

	if captureBehavior == nil {
		captureBehavior = defaultCaptureBehavior
	}

	return &AnalysisConfiguration{
		logger:                   logger,
		eventLogger:              eventLogger,
		eventFile:                file,
		PacketRateThreshold:      PacketThreshold,
		DestinationRateThreshold: destinationThreshold,
		Window:                   window,
		scanDetectionMode:        scanDetectionMode,
		showIdle:                 showIdle,
		savePackets:              savePackets,
		captureDir:               captureDir,
		buffers:                  buffers,
		ignoredIP:                ignored,
		context: AnalysisContext{
			srcIP:            srcIP,
			c2IP:             c2IP,
			sampleID:         sampleID,
			uninterestingIPs: filterIPs,
		},
		captureBehavior: captureBehavior,
		maxDestinations: defaultMaxDestinations,
	}
}

type BehaviorScope string

const (
	Global BehaviorScope = "global"
	Local  BehaviorScope = "local"
)

type BehaviorClass string // Classification of the behavior in a particular window

const (
	// local
	Attack             BehaviorClass = "attack"              // any attacking behavior
	OutboundConnection BehaviorClass = "outbound_connection" // normal connectivity behavior

	// global
	Scan BehaviorClass = "scanning" // any scanning behavior
	Idle BehaviorClass = "idle"     // absence of activity
)

type Behavior struct {
	Classification BehaviorClass `json:"classification"`
	Scope          BehaviorScope `json:"scope"`      // Indicates the scope of the behavior (global/local)
	Timestamp      time.Time     `json:"@timestamp"` // @timestamp to comply with Elastic

	PacketRate               float64 `json:"packet_rate"`
	PacketThreshold          float64 `json:"packet_threshold"`
	DestinationRate          float64 `json:"destination_rate"`
	DestinationRateThreshold float64 `json:"destination_rate_threshold"`

	SampleID string  `json:"sample_id"`
	SrcIP    *string `json:"src_ip"`
	C2IP     *string `json:"c2_ip"`

	// Destination IP/s depending on the scope
	DstIPs      *[]string    `json:"dst_ips"`
	DstIP       *string      `json:"dst_ip"`
	DstPort     *uint16      `json:"dst_port,omitempty"`
	Proto       string       `json:"proto,omitempty"`
	Destination *Destination `json:"destination,omitempty"`
}

// NewBehavior builds a Behavior with consistent context and destination wiring.
func NewBehavior(
	classification BehaviorClass,
	scope BehaviorScope,
	eventTime time.Time,
	packetRate float64,
	packetThreshold float64,
	destinationRate float64,
	destinationRateThreshold float64,
	destination *Destination,
	destinationLabels *[]string,
	context *AnalysisContext,
) *Behavior {
	if eventTime.IsZero() {
		eventTime = time.Now()
	}

	b := &Behavior{
		Classification:           classification,
		Scope:                    scope,
		Timestamp:                eventTime,
		PacketRate:               packetRate,
		PacketThreshold:          packetThreshold,
		DestinationRate:          destinationRate,
		DestinationRateThreshold: destinationRateThreshold,
	}

	if context != nil {
		if context.sampleID != "" {
			b.SampleID = context.sampleID
		}
		if context.srcIP != "" {
			b.SrcIP = &context.srcIP
		}
		if context.c2IP != "" {
			b.C2IP = &context.c2IP
		}
	}

	if destination != nil {
		destCopy := *destination
		if destCopy.IP != "" {
			dstIP := destCopy.IP
			b.DstIP = &dstIP
		}
		if destCopy.Port > 0 {
			port := destCopy.Port
			b.DstPort = &port
		}
		if destCopy.Protocol != "" {
			b.Proto = destCopy.Protocol
		}
		b.Destination = &destCopy
	}

	if destinationLabels != nil {
		b.DstIPs = destinationLabels
	}

	return b
}

// ProcessBatch processes a (subset) of a window of packets and saves
// intermediate results.
func (config *AnalysisConfiguration) ProcessBatch(
	_ []gopacket.Packet,
	batch []gopacket.Packet,
	windowStart time.Time,
) {
	if len(batch) == 0 {
		return
	}
	if config.result.windowStart.IsZero() {
		config.result.windowStart = windowStart
	}

	if config.savePackets > 0 {
		config.captureRecentPackets(batch)
	}

	maxTrackedDestinations := config.maxDestinations
	if maxTrackedDestinations <= 0 {
		maxTrackedDestinations = defaultMaxDestinations
	}
	globalPacketCount, destinationPacketCounts, err := countPacketsByDestination(
		&batch,
		&config.context.uninterestingIPs,
		maxTrackedDestinations,
	)
	if err != nil {
		var maxErr *MaxDestinationsReached
		if errors.As(err, &maxErr) {
			config.logger.Warn(
				"Maximum number of destinations reached; continuing with partial counts",
				"limit", maxTrackedDestinations,
			)
		} else {
			config.logger.Error("Error counting packet totals", "error", err)
		}
	}

	// Save intermediate results; normalization happens when the window flushes.
	config.result.globalPacketCount += globalPacketCount
	config.result.destinationPacketCounts = mergeDestinationCounts(
		config.result.destinationPacketCounts,
		destinationPacketCounts,
	)
}

func (config *AnalysisConfiguration) captureRecentPackets(batch []gopacket.Packet) {
	if config.savePackets <= 0 || len(batch) == 0 || config.buffers == nil {
		return
	}

	for _, packet := range batch {
		if packet == nil {
			continue
		}
		networkLayer := packet.NetworkLayer()
		if networkLayer == nil {
			continue
		}

		var hosts []string
		src := networkLayer.NetworkFlow().Src().String()
		if src != "" {
			hosts = append(hosts, src)
		}
		dst := networkLayer.NetworkFlow().Dst().String()
		if dst != "" {
			hosts = append(hosts, dst)
		}

		if len(hosts) == 0 {
			continue
		}

		seen := make(map[string]struct{}, len(hosts))
		for _, host := range hosts {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			config.appendPacketForHost(host, packet)
		}
	}
}

func (config *AnalysisConfiguration) appendPacketForHost(host string, packet gopacket.Packet) {
	if !config.shouldTrackHost(host) {
		return
	}

	buf, ok := config.buffers[host]
	if !ok {
		buf = newPacketRing(config.savePackets)
		config.buffers[host] = buf
	}
	buf.add(packet)
}

func (config *AnalysisConfiguration) shouldTrackHost(host string) bool {
	if host == "" || config.savePackets <= 0 {
		return false
	}
	if config.ignoredIP != nil {
		if _, skip := config.ignoredIP[host]; skip {
			return false
		}
	}
	return true
}

func (config *AnalysisConfiguration) snapshotHostPackets(host string) []gopacket.Packet {
	if config.buffers == nil {
		return nil
	}
	buf, ok := config.buffers[host]
	if !ok || buf == nil {
		return nil
	}
	return buf.snapshot()
}

func (config *AnalysisConfiguration) flushResults() {
	if config.result.globalPacketCount == 0 && len(config.result.destinationPacketCounts) == 0 {
		return
	}
	if config.result.windowStart.IsZero() {
		return
	}
	defer config.resetWindowState()

	windowDuration := config.Window
	if windowDuration <= 0 {
		config.logger.Warn(
			"Unable to normalize rates due to non-positive duration",
			"window", config.Window,
		)
		windowDuration = time.Second
	}
	durationSeconds := windowDuration.Seconds()
	windowEnd := config.result.windowStart.Add(windowDuration)

	mode := config.scanDetectionMode

	localBehaviors := make([]*Behavior, 0, len(config.result.destinationPacketCounts))
	attackHosts := make(map[string]struct{})
	for _, entry := range config.result.destinationPacketCounts {
		packetRate := float64(entry.Count) / durationSeconds
		localBehavior := config.classifyLocalBehavior(packetRate, entry.Destination, config.result.windowStart)
		if localBehavior == nil {
			continue
		}
		localBehaviors = append(localBehaviors, localBehavior)
		if localBehavior.Classification == Attack && localBehavior.DstIP != nil {
			attackHosts[*localBehavior.DstIP] = struct{}{}
		}
	}

	scanCounts := config.result.destinationPacketCounts
	if mode == ScanDetectionFilteredHostRate {
		scanCounts = config.filterNonAttackingDestinations(scanCounts, attackHosts)
	}
	scanDestinations := destinationsFromCounts(scanCounts)
	scanHosts := uniqueHosts(scanDestinations)
	scanTargets := scanHosts
	if mode == ScanDetectionNewHostRate {
		scanTargets = newHosts(scanHosts, config.previousScanHosts)
	}
	config.previousScanHosts = scanHosts

	config.logger.Debug(
		"Flushing results",
		"windowStart", config.result.windowStart,
		"windowEnd", windowEnd,
		"windowSeconds", durationSeconds,
		"globalPacketCount", config.result.globalPacketCount,
		"destinationPacketCounts", config.result.destinationPacketCounts,
		"windowDestinationCount", len(config.result.destinationPacketCounts),
		"scanDetectionMode", mode,
		"attackHostCount", len(attackHosts),
		"scanHostCount", len(scanHosts),
		"scanTargetCount", len(scanTargets),
	)

	// classify global behavior using local attack results
	globalPacketRate := float64(config.result.globalPacketCount) / durationSeconds
	scanRate := computeScanRate(durationSeconds, len(scanTargets))
	scanLabels := hostLabels(scanTargets)

	globalBehavior := config.classifyGlobalBehavior(
		globalPacketRate,
		scanRate,
		scanLabels,
		config.result.windowStart,
	)
	config.logBehavior(globalBehavior, nil)

	// then log local behavior
	capturedHosts := make(map[string]struct{})
	for _, localBehavior := range localBehaviors {
		if !config.shouldLogLocalBehavior(globalBehavior, localBehavior) {
			continue
		}
		var captured []gopacket.Packet
		var captureHost string
		if localBehavior != nil && localBehavior.DstIP != nil {
			captureHost = *localBehavior.DstIP
		}

		if capture, err := config.captureBehavior(config, localBehavior); err != nil {
			config.logger.Error("Failed to capture packets", "error", err)
		} else if capture && captureHost != "" {
			if _, seen := capturedHosts[captureHost]; seen {
				config.logger.Debug("Skipping duplicate capture for host", "host", captureHost)
			} else {
				capturedHosts[captureHost] = struct{}{}
				captured = config.snapshotHostPackets(captureHost)
			}
		}
		config.logBehavior(localBehavior, captured)
	}

}

func (config *AnalysisConfiguration) resetWindowState() {
	config.result = batchResult{}
	if config.savePackets <= 0 {
		config.buffers = nil
		return
	}
	if config.buffers == nil {
		config.buffers = make(map[string]*packetRing)
		return
	}
	clear(config.buffers)
}

func (config *AnalysisConfiguration) logBehavior(
	behavior *Behavior,
	packets []gopacket.Packet,
) {
	if behavior == nil {
		return
	}

	switch behavior.Classification {
	case Idle:
		if !config.showIdle {
			return
		}
		config.summary.IdleEvents++
	case Attack:
		var captured bool
		if config.savePackets > 0 {
			captured = config.persistPackets(behavior, packets)
			if captured {
				config.summary.SavedCaptures++
			}
		}
		config.summary.AttackEvents++
	case Scan:
		config.summary.ScanEvents++
	case OutboundConnection:
		// outbound events are logged to Eve but don't alter the summary
	default:
		return
	}

	if config.eventLogger == nil {
		return
	}

	if err := config.eventLogger.LogBehavior(behavior); err != nil {
		config.logger.Error("Failed to write eve event", "error", err)
	} else {
		config.logger.Debug(
			"Emitted eve event",
			"classification", behavior.Classification,
			"scope", behavior.Scope,
		)
	}
}

func (config *AnalysisConfiguration) persistPackets(behavior *Behavior, packets []gopacket.Packet) bool {
	if config.savePackets <= 0 || behavior == nil {
		return false
	}

	data := packets
	if len(data) == 0 && behavior.DstIP != nil {
		data = config.snapshotHostPackets(*behavior.DstIP)
	}
	if len(data) == 0 {
		return false
	}

	path, err := WriteBehaviorCapture(config.captureDir, behavior, data, config.linkType)
	if err != nil {
		config.logger.Error(
			"Failed to write captured packets",
			"error", err,
		)
		return false
	}
	if path != "" {
		config.logger.Info(
			"Saved attack packet capture",
			"path", path,
			"count", len(data),
		)
		return true
	}
	return false
}

func (config *AnalysisConfiguration) classifyLocalBehavior(
	packetRate float64,
	destination Destination,
	eventTime time.Time,
) *Behavior {
	destCopy := destination // avoid referencing loop variable

	config.logger.Debug(
		"Classifying local behavior",
		"packetRate", packetRate,
		"threshold", config.PacketRateThreshold,
		"destination", destCopy.String(),
		"protocol", destCopy.Protocol,
	)

	// attacks can only occur if a C2 IP is specified (assumed)
	if config != nil && config.context.c2IP != "" && packetRate > config.PacketRateThreshold {
		return NewBehavior(
			Attack,
			Local,
			eventTime,
			packetRate,
			config.PacketRateThreshold,
			0,
			0,
			&destCopy,
			nil,
			&config.context,
		)
	}
	return NewBehavior(
		OutboundConnection,
		Local,
		eventTime,
		packetRate,
		config.PacketRateThreshold,
		0,
		0,
		&destCopy,
		nil,
		&config.context,
	)
}

func (config *AnalysisConfiguration) shouldLogLocalBehavior(globalBehavior *Behavior, localBehavior *Behavior) bool {
	if localBehavior == nil {
		return false
	}
	if globalBehavior == nil {
		return true
	}
	return !(globalBehavior.Classification == Scan && localBehavior.Classification == OutboundConnection)
}

func (config *AnalysisConfiguration) classifyGlobalBehavior(
	globalPacketRate float64,
	scanRate float64,
	scanLabels *[]string,
	eventTime time.Time,
) *Behavior {
	if globalPacketRate > config.PacketRateThreshold {
		config.logger.Debug(
			"Detected global high packet rate",
			"scope", Global,
			"eventTime", eventTime,
			"packetRate", globalPacketRate,
			"threshold", config.PacketRateThreshold,
		)
	}

	// detected a horizontal scan when the host rate exceeds the configured threshold,
	// regardless of whether the packet-rate condition was satisfied
	if scanRate > config.DestinationRateThreshold {
		config.logger.Debug(
			"Detected horizontal scan host rate",
			"scope", Global,
			"eventTime", eventTime,
			"hostRate", scanRate,
			"scanDetectionMode", config.scanDetectionMode,
			"threshold", config.DestinationRateThreshold,
		)

		return NewBehavior(
			Scan,
			Global,
			eventTime,
			globalPacketRate,
			config.PacketRateThreshold,
			scanRate,
			config.DestinationRateThreshold,
			nil,
			scanLabels,
			&config.context,
		)
	}

	return NewBehavior(
		Idle,
		Global,
		eventTime,
		globalPacketRate,
		config.PacketRateThreshold,
		scanRate,
		config.DestinationRateThreshold,
		nil,
		scanLabels,
		&config.context,
	)
}

func (config *AnalysisConfiguration) filterNonAttackingDestinations(destinations destinationCounts, attackHosts map[string]struct{}) destinationCounts {
	if len(destinations) == 0 {
		return nil
	}
	if len(attackHosts) == 0 {
		return destinations
	}

	filtered := make(destinationCounts, len(destinations))
	for key, entry := range destinations {
		if entry.Destination.IP == "" {
			continue
		}
		if _, isAttackHost := attackHosts[entry.Destination.IP]; isAttackHost {
			continue
		}
		filtered[key] = entry
	}

	if len(filtered) == 0 {
		return nil
	}

	return filtered
}

func destinationsFromCounts(destinations destinationCounts) []Destination {
	if len(destinations) == 0 {
		return nil
	}

	list := make([]Destination, 0, len(destinations))
	for _, entry := range destinations {
		if entry.Destination.IP == "" {
			continue
		}
		list = append(list, entry.Destination)
	}

	if len(list) == 0 {
		return nil
	}

	return list
}

func uniqueHosts(destinations []Destination) []Destination {
	if len(destinations) == 0 {
		return nil
	}

	hosts := make([]Destination, 0, len(destinations))
	for _, destination := range destinations {
		if destination.IP == "" {
			continue
		}
		seen := false
		for _, host := range hosts {
			if destination.HostEquals(host) {
				seen = true
				break
			}
		}
		if !seen {
			hosts = append(hosts, destination)
		}
	}

	if len(hosts) == 0 {
		return nil
	}

	return hosts
}

func newHosts(current []Destination, previous []Destination) []Destination {
	if len(current) == 0 {
		return nil
	}
	if len(previous) == 0 {
		return current
	}

	var out []Destination
	for _, destination := range current {
		seen := false
		for _, prev := range previous {
			if destination.HostEquals(prev) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, destination)
		}
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func computeScanRate(durationSeconds float64, hostCount int) float64 {
	if durationSeconds <= 0 || hostCount <= 0 {
		return 0
	}

	return float64(hostCount) / durationSeconds
}

func hostLabels(hosts []Destination) *[]string {
	if len(hosts) == 0 {
		return nil
	}

	labels := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host.IP == "" {
			continue
		}
		labels = append(labels, host.IP)
	}

	if len(labels) == 0 {
		return nil
	}

	sort.Strings(labels)
	return &labels
}

func (config *AnalysisConfiguration) Close() error {
	if config == nil || config.eventFile == nil {
		return nil
	}
	err := config.eventFile.Close()
	config.eventFile = nil
	return err
}

func (config *AnalysisConfiguration) Summary() AnalysisSummary {
	if config == nil {
		return AnalysisSummary{}
	}
	return config.summary
}

func defaultCaptureBehavior(config *AnalysisConfiguration, behavior *Behavior) (bool, error) {
	if config == nil {
		return false, errors.New("config is nil")
	}
	if behavior == nil {
		return false, nil
	}
	return (behavior.Classification == Attack &&
		behavior.DstIP != nil &&
		config.savePackets > 0), nil
}
