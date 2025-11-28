package internal

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// == Analysis

type AnalysisConfiguration struct {
	// configuration
	PacketRateThreshold float64
	IPRateThreshold     float64
	Window              time.Duration
	maxHosts            map[string]int // maximum number of hosts to analyze

	// extra logging options
	showIdle    bool // emit idle windows when requested
	savePackets int  // number of packets to save, 0 means no packets are saved
	captureDir  string
	linkType    layers.LinkType

	// instance references
	eventFile   *os.File
	logger      *slog.Logger
	eventLogger *EveLogger

	result          batchResult
	buffers         map[string]*packetRing
	ignoredIP       map[string]struct{}
	summary         AnalysisSummary
	captureBehavior func(*AnalysisConfiguration, *Behavior) (bool, error)

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

type batchResult struct {
	windowStart       time.Time
	hostPacketCounts  map[string]int
	globalPacketCount int
	globalNewIPCount  int
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
	IPThreshold float64,
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
		logger:              logger,
		eventLogger:         eventLogger,
		eventFile:           file,
		PacketRateThreshold: PacketThreshold,
		IPRateThreshold:     IPThreshold,
		Window:              window,
		showIdle:            showIdle,
		savePackets:         savePackets,
		captureDir:          captureDir,
		buffers:             buffers,
		ignoredIP:           ignored,
		context: AnalysisContext{
			srcIP:            srcIP,
			c2IP:             c2IP,
			sampleID:         sampleID,
			uninterestingIPs: filterIPs,
		},
		captureBehavior: captureBehavior,
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

	PacketRate      float64 `json:"packet_rate"`
	PacketThreshold float64 `json:"packet_threshold"`
	IPRate          float64 `json:"ip_rate"`
	IPRateThreshold float64 `json:"ip_rate_threshold"`

	SampleID string  `json:"sample_id"`
	SrcIP    *string `json:"src_ip"`
	C2IP     *string `json:"c2_ip"`

	// Destination IP/s depending on the scope
	DstIPs *[]string `json:"dst_ips"`
	DstIP  *string   `json:"dst_ip"`
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

	const maxTrackedHosts = 512
	globalPacketCount, localPacketCounts, err := countPacketsByHost(
		&batch,
		&config.context.uninterestingIPs,
		maxTrackedHosts,
	)
	if err != nil {
		var maxErr *MaxHostsReached
		if errors.As(err, &maxErr) {
			config.logger.Warn(
				"Maximum number of hosts reached; continuing with partial counts",
				"limit", maxTrackedHosts,
			)
		} else {
			config.logger.Error("Error counting packet totals", "error", err)
		}
	}

	// Save intermediate results; normalization happens when the window flushes.
	config.result.globalPacketCount += globalPacketCount
	var newHostCount int
	config.result.hostPacketCounts, newHostCount = mergeHostCounts(
		config.result.hostPacketCounts,
		localPacketCounts,
	)
	config.result.globalNewIPCount += newHostCount
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
	if config.result.globalPacketCount == 0 && len(config.result.hostPacketCounts) == 0 {
		return
	}
	if config.result.windowStart.IsZero() {
		return
	}
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

	config.logger.Debug(
		"Flushing results",
		"windowStart", config.result.windowStart,
		"windowEnd", windowEnd,
		"windowSeconds", durationSeconds,
		"globalPacketCount", config.result.globalPacketCount,
		"hostPacketCounts", config.result.hostPacketCounts,
		"globalNewIPCount", config.result.globalNewIPCount,
	)

	// first classify global behavior since it can be used by the local behavior
	globalPacketRate := float64(config.result.globalPacketCount) / durationSeconds
	globalIPRate := float64(config.result.globalNewIPCount) / durationSeconds

	globalBehavior := config.classifyGlobalBehavior(
		globalPacketRate,
		globalIPRate,
		nil,
		config.result.windowStart,
	)
	config.logBehavior(globalBehavior, nil)

	// then classify local behavior
	for host, count := range config.result.hostPacketCounts {
		packetRate := float64(count) / durationSeconds
		localBehavior := config.classifyLocalBehavior(packetRate, host, config.result.windowStart, globalBehavior)
		var captured []gopacket.Packet

		if capture, err := config.captureBehavior(config, localBehavior); err != nil {
			config.logger.Error("Failed to capture packets", "error", err)
		} else if capture {
			captured = config.snapshotHostPackets(*localBehavior.DstIP)
		}
		config.logBehavior(localBehavior, captured)
	}

	config.result = batchResult{}
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
	destinationIP string,
	eventTime time.Time,
	globalBehavior *Behavior,
) *Behavior {
	config.logger.Debug(
		"Classifying local behavior",
		"packetRate", packetRate,
		"threshold", config.PacketRateThreshold,
		"destinationIP", destinationIP,
	)

	// attacks can only occur if a C2 IP is specified (assumed)
	if config.context.c2IP != "" && packetRate > config.PacketRateThreshold {
		return &Behavior{
			Classification:  Attack,
			Scope:           Local,
			Timestamp:       eventTime,
			PacketRate:      packetRate,
			PacketThreshold: config.PacketRateThreshold,
			IPRate:          0,
			IPRateThreshold: 0,
			DstIP:           &destinationIP,
			SrcIP:           &config.context.srcIP,
			SampleID:        config.context.sampleID,
		}
	}
	// if no c2 is specified, or it's a low packet rate, it might be a regular connection
	// if, however, globally a scan was detected, we cannot determine whether it's part of the scan or not
	if globalBehavior != nil && globalBehavior.Classification == Scan {
		return nil
	}
	return &Behavior{
		Classification:  OutboundConnection,
		Scope:           Local,
		Timestamp:       eventTime,
		PacketRate:      packetRate,
		PacketThreshold: config.PacketRateThreshold,
		IPRate:          0,
		IPRateThreshold: 0,
		DstIP:           &destinationIP,
		SrcIP:           &config.context.srcIP,
		SampleID:        config.context.sampleID,
	}
}

func (config *AnalysisConfiguration) classifyGlobalBehavior(
	globalPacketRate float64,
	newIPRate float64,
	destinationIPs *[]string,
	eventTime time.Time,
) *Behavior {
	// found an anomalous activity
	if globalPacketRate > config.PacketRateThreshold {
		config.logger.Debug(
			"Detected global high packet rate",
			"scope", Global,
			"eventTime", eventTime,
			"packetRate", globalPacketRate,
			"threshold", config.PacketRateThreshold,
		)

		// detected a scan
		if newIPRate > config.IPRateThreshold {
			config.logger.Debug(
				"Detected high new IP rate",
				"scope", Global,
				"eventTime", eventTime,
				"newIPRate", newIPRate,
				"threshold", config.IPRateThreshold,
			)

			return &Behavior{
				Classification:  Scan,
				Scope:           Global,
				Timestamp:       eventTime,
				PacketRate:      globalPacketRate,
				PacketThreshold: config.PacketRateThreshold,
				IPRate:          newIPRate,
				IPRateThreshold: config.IPRateThreshold,
				SrcIP:           &config.context.srcIP,
				DstIPs:          destinationIPs,
				C2IP:            &config.context.c2IP,
				SampleID:        config.context.sampleID,
			}
		}
	}

	return &Behavior{
		Classification:  Idle,
		Scope:           Global,
		Timestamp:       eventTime,
		PacketRate:      globalPacketRate,
		PacketThreshold: config.PacketRateThreshold,
		IPRate:          newIPRate,
		IPRateThreshold: config.IPRateThreshold,
		SrcIP:           &config.context.srcIP,
		DstIPs:          destinationIPs,
		C2IP:            &config.context.c2IP,
		SampleID:        config.context.sampleID,
	}
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
