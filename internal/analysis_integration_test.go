package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"log/slog"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestEveAttackFormatting(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 10)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 8080),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	attack := findEventByCategory(events, "attack")
	if attack == nil {
		t.Fatalf("expected attack alert, got %v", events)
	}

	if attack.DestIP != "198.51.100.10" {
		t.Fatalf("expected DestIP 198.51.100.10, got %s", attack.DestIP)
	}
	if attack.DestPort != 8080 {
		t.Fatalf("expected DestPort 8080, got %d", attack.DestPort)
	}
	if attack.Proto != "tcp" {
		t.Fatalf("expected Proto tcp, got %s", attack.Proto)
	}
	if attack.Host != "sample-1" {
		t.Fatalf("expected Host sample-1, got %s", attack.Host)
	}

	gomon := attack.Gomon
	if gomon == nil || gomon.C2IP == nil || *gomon.C2IP != "203.0.113.50" {
		t.Fatalf("expected gomon.c2_ip 203.0.113.50, got %#v", gomon)
	}
	if gomon.PacketThreshold != 1 {
		t.Fatalf("expected packet_threshold 1, got %v", gomon.PacketThreshold)
	}
}

func TestEveScanFormatting(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 3)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.1", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.2", 2323),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.3", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.4", 80),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	scan := findEventByCategory(events, "scan")
	if scan == nil {
		t.Fatalf("expected scan alert, got %v", events)
	}

	if scan.DestIP != "0.0.0.0" {
		t.Fatalf("expected DestIP 0.0.0.0 for multi-destination scan, got %s", scan.DestIP)
	}
	if scan.Alert == nil || scan.Alert.Signature == "" {
		t.Fatalf("expected alert signature, got %#v", scan.Alert)
	}

	gomon := scan.Gomon
	if gomon == nil || gomon.C2IP == nil || *gomon.C2IP != "203.0.113.50" {
		t.Fatalf("expected gomon.c2_ip 203.0.113.50, got %#v", gomon)
	}
	if gomon.IPRate < 3 {
		t.Fatalf("expected ip_rate >= 3, got %v", gomon.IPRate)
	}
}

func TestOutboundSuppressedDuringScan(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 2)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.11", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.12", 80),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())

	scan := findEventByCategory(events, "scan")
	if scan == nil {
		t.Fatalf("expected scan alert, got %v", events)
	}
	if conn := findEventByCategory(events, "connection"); conn != nil {
		t.Fatalf("expected no outbound connection events during scan, got %v", conn)
	}
}

func TestAttackDestinationNotLoggedAsOutbound(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 10)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.20", 9001),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.30", 443),
	}

	windowStart := time.Now()
	config.ProcessBatch(nil, packets, windowStart)
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())

	attack := findEventByCategory(events, "attack")
	if attack == nil {
		t.Fatalf("expected attack alert, got %v", events)
	}
	connections := findEventsByCategory(events, "connection")
	if len(connections) == 0 {
		t.Fatalf("expected outbound connection event for non-attack destination, got %v", events)
	}
	for _, conn := range connections {
		if conn.DestIP == attack.DestIP && conn.DestPort == attack.DestPort {
			t.Fatalf("attack destination %s:%d also logged as outbound connection: %#v", conn.DestIP, conn.DestPort, conn)
		}
	}
}

func TestSingleDestinationBurstDoesNotTriggerScan(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "203.0.113.50", 1, 3)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.10", 22),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if scan := findEventByCategory(events, "scan"); scan != nil {
		t.Fatalf("unexpected scan alert for single destination: %#v", scan)
	}
	if attack := findEventByCategory(events, "attack"); attack == nil {
		t.Fatalf("expected attack alert for single destination burst, got %v", events)
	}
}

func TestScanEmittedWithoutC2(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 1, 2)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.1", 80),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.2", 81),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.3", 82),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if scan := findEventByCategory(events, "scan"); scan == nil {
		t.Fatalf("expected scan alert without C2 configured, got %v", events)
	}
	if attack := findEventByCategory(events, "attack"); attack != nil {
		t.Fatalf("did not expect attack alert without C2, got %#v", attack)
	}
}

func TestMultiPortSingleHostTriggersScan(t *testing.T) {
	buf := &bytes.Buffer{}
	config := newTestAnalysisConfigWithC2(buf, "", 1, 2)

	packets := []gopacket.Packet{
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 22),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 23),
		buildTestPacket(t, layers.IPProtocolTCP, "198.51.100.200", 24),
	}

	config.ProcessBatch(nil, packets, time.Now())
	config.flushResults()

	events := parseEveEvents(t, buf.Bytes())
	if scan := findEventByCategory(events, "scan"); scan == nil {
		t.Fatalf("expected scan alert for multi-port single host, got %v", events)
	}
	if attack := findEventByCategory(events, "attack"); attack != nil {
		t.Fatalf("did not expect attack alert for multi-port scan, got %#v", attack)
	}
}

func newTestAnalysisConfigWithC2(w io.Writer, c2 string, packetThresh, ipThresh float64) *AnalysisConfiguration {
	config := NewAnalysisConfiguration(
		"10.0.0.5",
		c2,
		nil,
		false,
		time.Second,
		"",
		packetThresh,
		ipThresh,
		slog.LevelError,
		"sample-1",
		0,
		"",
		nil,
	)

	if w != nil {
		config.eventLogger = NewEveLogger(w)
	}
	config.logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	return config
}

type parsedEveEvent struct {
	EventType string        `json:"event_type"`
	Host      string        `json:"host"`
	SrcIP     string        `json:"src_ip"`
	DestIP    string        `json:"dest_ip"`
	DestPort  uint16        `json:"dest_port"`
	Proto     string        `json:"proto"`
	Alert     *parsedAlert  `json:"alert"`
	Gomon     *parsedGomon  `json:"gomon"`
	Metadata  metadataUnion `json:"metadata"`
}

type metadataUnion map[string]json.RawMessage

func (m *metadataUnion) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*m = raw
	return nil
}

type parsedAlert struct {
	Category  string `json:"category"`
	Signature string `json:"signature"`
}

type parsedGomon struct {
	C2IP            *string `json:"c2_ip"`
	PacketRate      float64 `json:"packet_rate"`
	PacketThreshold float64 `json:"packet_threshold"`
	IPRate          float64 `json:"ip_rate"`
	IPRateThreshold float64 `json:"ip_rate_threshold"`
	DestPort        *uint16 `json:"dest_port"`
	Proto           string  `json:"proto"`
}

func parseEveEvents(t *testing.T, data []byte) []parsedEveEvent {
	t.Helper()

	var events []parsedEveEvent
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev parsedEveEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("failed to unmarshal eve event: %v (line: %s)", err, line)
		}
		if gomonRaw, ok := ev.Metadata["gomon"]; ok && len(gomonRaw) > 0 {
			var gm parsedGomon
			if err := json.Unmarshal(gomonRaw, &gm); err != nil {
				t.Fatalf("failed to unmarshal gomon metadata: %v", err)
			}
			ev.Gomon = &gm
		}
		events = append(events, ev)
	}

	return events
}

func findEventByCategory(events []parsedEveEvent, category string) *parsedEveEvent {
	for i := range events {
		if events[i].Alert != nil && events[i].Alert.Category == category {
			return &events[i]
		}
	}
	return nil
}

func findEventsByCategory(events []parsedEveEvent, category string) []parsedEveEvent {
	var matches []parsedEveEvent
	for _, ev := range events {
		if ev.Alert != nil && ev.Alert.Category == category {
			matches = append(matches, ev)
		}
	}
	return matches
}

func buildTestPacket(t *testing.T, proto layers.IPProtocol, dstIP string, dstPort uint16) gopacket.Packet {
	t.Helper()

	srcIP := net.IPv4(10, 0, 0, 5)
	dst := net.ParseIP(dstIP)
	if dst == nil {
		t.Fatalf("invalid dst ip %q", dstIP)
	}

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    srcIP,
		DstIP:    dst,
		Protocol: proto,
	}

	var transport gopacket.SerializableLayer
	switch proto {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{
			SrcPort: 40000,
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
			Window:  14600,
		}
		tcp.SetNetworkLayerForChecksum(&ip)
		transport = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(40000),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(&ip)
		transport = udp
	default:
		t.Fatalf("unsupported proto: %v", proto)
	}

	payload := gopacket.Payload([]byte{0x01, 0x02, 0x03, 0x04})
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}

	if err := gopacket.SerializeLayers(buffer, opts, &eth, &ip, transport, payload); err != nil {
		t.Fatalf("failed to serialize packet: %v", err)
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buffer.Bytes()),
		Length:        len(buffer.Bytes()),
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	packet.Metadata().CaptureInfo = ci

	return packet
}
