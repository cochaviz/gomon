package internal

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"sync"
	"time"
)

const eveTimestampFormat = "2006-01-02T15:04:05.000000Z07:00"

// EveLogger serializes events that mimic Suricata's eve JSON output.
type EveLogger struct {
	encoder *json.Encoder
	mu      sync.Mutex
}

// EveEvent matches the general shape of Suricata eve records.
type EveEvent struct {
	Timestamp string         `json:"timestamp"`
	EventType string         `json:"event_type"`
	Host      string         `json:"host,omitempty"`
	SrcIP     string         `json:"src_ip,omitempty"`
	DestIP    string         `json:"dest_ip,omitempty"`
	DestPort  uint16         `json:"dest_port,omitempty"`
	Proto     string         `json:"proto,omitempty"`
	FlowID    uint64         `json:"flow_id,omitempty"`
	Alert     *EveAlert      `json:"alert,omitempty"`
	Stats     *EveStats      `json:"stats,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type EveAlert struct {
	Action      string `json:"action,omitempty"`
	GID         int    `json:"gid,omitempty"`
	SignatureID int    `json:"signature_id,omitempty"`
	Rev         int    `json:"rev,omitempty"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

type EveStats struct {
	Flow *EveFlowStats `json:"flow,omitempty"`
}

type EveFlowStats struct {
	PacketRate      float64 `json:"packet_rate,omitempty"`
	PacketThreshold float64 `json:"packet_threshold,omitempty"`
	IPRate          float64 `json:"ip_rate,omitempty"`
	IPRateThreshold float64 `json:"ip_rate_threshold,omitempty"`
}

// EveDetails keeps gomon specific metadata grouped under a dedicated object.
type EveDetails struct {
	Scope           BehaviorScope `json:"scope,omitempty"`
	C2IP            *string       `json:"c2_ip,omitempty"` // easier handling of nil values from behavior
	PacketRate      float64       `json:"packet_rate,omitempty"`
	PacketThreshold float64       `json:"packet_threshold,omitempty"`
	IPRate          float64       `json:"ip_rate,omitempty"`
	IPRateThreshold float64       `json:"ip_rate_threshold,omitempty"`
	DestPort        *uint16       `json:"dest_port,omitempty"`
	Proto           string        `json:"proto,omitempty"`
}

func NewEveLogger(w io.Writer) *EveLogger {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return &EveLogger{
		encoder: encoder,
	}
}

func (l *EveLogger) LogBehavior(behavior *Behavior) error {
	if l == nil || behavior == nil {
		return nil
	}

	event := behaviorToEveEvent(behavior)
	if event == nil {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	return l.encoder.Encode(event)
}

func behaviorToEveEvent(behavior *Behavior) *EveEvent {
	if behavior == nil {
		return nil
	}

	event := &EveEvent{
		EventType: eventTypeFromBehavior(behavior),
		FlowID:    flowIDFromBehavior(behavior),
		Alert:     newEveAlertFromBehavior(behavior),
		Stats:     newEveStats(behavior),
		Metadata:  eventMetadataFromBehavior(behavior),
	}

	timestamp := behavior.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	event.Timestamp = timestamp.UTC().Format(eveTimestampFormat)

	if behavior.SrcIP != nil {
		event.SrcIP = *behavior.SrcIP
	}
	if behavior.SampleID != "" {
		event.Host = behavior.SampleID
	}

	if behavior.DstIP != nil && *behavior.DstIP != "" {
		event.DestIP = *behavior.DstIP
	}

	if event.DestIP == "" && behavior.DstIPs != nil {
		switch len(*behavior.DstIPs) {
		case 0:
		case 1:
			event.DestIP = (*behavior.DstIPs)[0]
		default:
			event.DestIP = "0.0.0.0"
		}
	}

	if event.DestIP == "" {
		event.DestIP = "0.0.0.0"
	}

	if behavior.DstPort != nil {
		event.DestPort = *behavior.DstPort
	}
	if behavior.Proto != "" {
		event.Proto = behavior.Proto
	}

	return event
}

func eventTypeFromBehavior(behavior *Behavior) string {
	switch behavior.Classification {
	case Attack, Scan, OutboundConnection:
		return "alert"
	default:
		return "stats"
	}
}

func newEveAlertFromBehavior(behavior *Behavior) *EveAlert {
	switch behavior.Classification {
	case Attack, Scan, OutboundConnection:
	default:
		return nil
	}

	return &EveAlert{
		Action:      "allowed",
		GID:         5, // GID for `gomon` alerts to allow proper categorization
		SignatureID: signatureIDForBehavior(behavior.Classification),
		Rev:         1,
		Signature:   signatureForBehavior(behavior),
		Category:    categoryForBehavior(behavior.Classification),
		Severity:    severityForBehavior(behavior.Classification),
	}
}

func newEveStats(behavior *Behavior) *EveStats {
	if behavior == nil || behavior.Classification != Idle {
		return nil
	}

	return &EveStats{
		Flow: &EveFlowStats{
			PacketRate:      behavior.PacketRate,
			PacketThreshold: behavior.PacketThreshold,
			IPRate:          behavior.IPRate,
			IPRateThreshold: behavior.IPRateThreshold,
		},
	}
}

func newEveDetails(behavior *Behavior) *EveDetails {
	if behavior == nil {
		return nil
	}

	d := &EveDetails{
		Scope:           behavior.Scope,
		C2IP:            behavior.C2IP,
		PacketRate:      behavior.PacketRate,
		PacketThreshold: behavior.PacketThreshold,
		IPRate:          behavior.IPRate,
		IPRateThreshold: behavior.IPRateThreshold,
		DestPort:        behavior.DstPort,
		Proto:           behavior.Proto,
	}

	return d
}

func eventMetadataFromBehavior(behavior *Behavior) map[string]any {
	if behavior == nil {
		return nil
	}

	meta := make(map[string]any)

	if details := newEveDetails(behavior); details != nil {
		meta["gomon"] = details
	}

	if len(meta) == 0 {
		return nil
	}

	return meta
}

func signatureForBehavior(behavior *Behavior) string {
	switch behavior.Classification {
	case Attack:
		return "gomon high packet-rate to single host"
	case Scan:
		return "gomon destination scan volume exceeded"
	case OutboundConnection:
		return "gomon outbound connection observed"
	default:
		return "gomon event"
	}
}

func categoryForBehavior(class BehaviorClass) string {
	switch class {
	case Attack:
		return "attack"
	case Scan:
		return "scan"
	case OutboundConnection:
		return "connection"
	default:
		return "unsuspicious"
	}
}

func severityForBehavior(class BehaviorClass) int {
	switch class {
	case Attack:
		return 2
	case Scan:
		return 3
	case OutboundConnection:
		return 1
	default:
		return 1
	}
}

func signatureIDForBehavior(class BehaviorClass) int {
	switch class {
	case Attack:
		return 2100001
	case Scan:
		return 2100002
	case OutboundConnection:
		return 2100003
	default:
		return 2100000
	}
}

func flowIDFromBehavior(behavior *Behavior) uint64 {
	hasher := fnv.New64a()

	add := func(value string) {
		if value == "" {
			return
		}
		_, _ = hasher.Write([]byte(value))
	}

	add(string(behavior.Classification))
	add(string(behavior.Scope))

	if behavior.SrcIP != nil {
		add(*behavior.SrcIP)
	}
	if behavior.DstIP != nil {
		add(*behavior.DstIP)
	}
	if behavior.DstPort != nil {
		add(fmt.Sprintf("%d", *behavior.DstPort))
	}
	if behavior.Proto != "" {
		add(behavior.Proto)
	}
	if behavior.DstIPs != nil {
		for _, ip := range *behavior.DstIPs {
			add(ip)
		}
	}

	timestamp := behavior.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}
	add(timestamp.UTC().Format(time.RFC3339Nano))

	return hasher.Sum64()
}
