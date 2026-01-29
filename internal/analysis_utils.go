package internal

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type MaxDestinationsReached struct{}

func (e *MaxDestinationsReached) Error() string {
	return "maximum number of destinations reached"
}

// Destination identifies a remote endpoint using IP, port, and protocol.
type Destination struct {
	IP       string `json:"ip"`
	Port     uint16 `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// Equals returns true when the destinations match by IP and port.
func (d Destination) Equals(other Destination) bool {
	return d.IP == other.IP && d.Port == other.Port
}

// HostEquals returns true when the destinations share the same host IP.
func (d Destination) HostEquals(other Destination) bool {
	return d.IP == other.IP
}

// String renders a human-readable endpoint label.
func (d Destination) String() string {
	base := d.IP
	if d.Port > 0 {
		base = fmt.Sprintf("%s:%d", base, d.Port)
	}
	if d.Protocol != "" {
		return fmt.Sprintf("%s/%s", base, strings.ToLower(d.Protocol))
	}
	return base
}

type destinationKey struct {
	IP   string
	Port uint16
}

func destinationKeyFor(destination Destination) destinationKey {
	return destinationKey{IP: destination.IP, Port: destination.Port}
}

type destinationCount struct {
	Destination Destination
	Count       int
}

type destinationCounts map[destinationKey]destinationCount

func topDestinationByCount(destinations destinationCounts) (Destination, int) {
	if len(destinations) == 0 {
		return Destination{}, 0
	}

	var (
		maxDest  Destination
		maxCount int
		maxLabel string
		found    bool
	)

	for _, entry := range destinations {
		if entry.Count <= 0 {
			continue
		}
		label := entry.Destination.String()
		if !found || entry.Count > maxCount || (entry.Count == maxCount && label < maxLabel) {
			maxCount = entry.Count
			maxDest = entry.Destination
			maxLabel = label
			found = true
		}
	}

	if !found {
		return Destination{}, 0
	}

	return maxDest, maxCount
}

type packetRing struct {
	max   int
	items []gopacket.Packet
}

func newPacketRing(max int) *packetRing {
	if max <= 0 {
		max = 1
	}
	return &packetRing{
		max:   max,
		items: make([]gopacket.Packet, 0, max),
	}
}

func (r *packetRing) add(packet gopacket.Packet) {
	if r == nil || r.max <= 0 {
		return
	}
	if len(r.items) < r.max {
		r.items = append(r.items, packet)
		return
	}
	copy(r.items, r.items[1:])
	r.items[len(r.items)-1] = packet
}

func (r *packetRing) snapshot() []gopacket.Packet {
	if r == nil || len(r.items) == 0 {
		return nil
	}
	out := make([]gopacket.Packet, len(r.items))
	copy(out, r.items)
	return out
}

func mergeDestinationCounts(acc destinationCounts, batch destinationCounts) destinationCounts {
	if len(batch) == 0 {
		return acc
	}

	if acc == nil {
		acc = make(destinationCounts, len(batch))
	}

	for key, entry := range batch {
		if entry.Count == 0 {
			continue
		}
		if existing, exists := acc[key]; exists {
			existing.Count += entry.Count
			if existing.Destination.Protocol == "" && entry.Destination.Protocol != "" {
				existing.Destination.Protocol = entry.Destination.Protocol
			}
			acc[key] = existing
		} else {
			acc[key] = entry
		}
	}

	return acc
}

// countPacketsByDestination tallies packets overall and per destination endpoint.
func countPacketsByDestination(
	pkts *[]gopacket.Packet,
	excludeIPs *[]string,
	maxDestinations int,
) (int, destinationCounts, error) {
	if pkts == nil || len(*pkts) == 0 {
		return 0, nil, nil
	}

	hostCounts := make(destinationCounts, maxDestinations)
	total := 0

	var exclude map[string]struct{}
	if excludeIPs != nil && len(*excludeIPs) > 0 {
		exclude = make(map[string]struct{}, len(*excludeIPs))
		for _, ip := range *excludeIPs {
			if ip == "" {
				continue
			}
			exclude[ip] = struct{}{}
		}
	}

	for _, packet := range *pkts {
		if packet == nil {
			continue
		}
		destination := destinationFromPacket(packet)
		if destination.IP == "" {
			continue
		}

		if _, skip := exclude[destination.IP]; skip {
			continue
		}

		total++

		key := destinationKeyFor(destination)
		if entry, exists := hostCounts[key]; exists {
			entry.Count++
			if entry.Destination.Protocol == "" && destination.Protocol != "" {
				entry.Destination.Protocol = destination.Protocol
			}
			hostCounts[key] = entry
			continue
		}

		if len(hostCounts) >= maxDestinations {
			return total, hostCounts, &MaxDestinationsReached{}
		}

		hostCounts[key] = destinationCount{
			Destination: destination,
			Count:       1,
		}
	}

	return total, hostCounts, nil
}

func destinationFromPacket(packet gopacket.Packet) Destination {
	var out Destination
	if packet == nil {
		return out
	}

	if network := packet.NetworkLayer(); network != nil {
		out.IP = network.NetworkFlow().Dst().String()
		if out.Protocol == "" {
			out.Protocol = strings.ToLower(network.LayerType().String())
		}
	}

	if transport := packet.TransportLayer(); transport != nil {
		switch layer := transport.(type) {
		case *layers.TCP:
			out.Port = uint16(layer.DstPort)
			out.Protocol = "tcp"
		case *layers.UDP:
			out.Port = uint16(layer.DstPort)
			out.Protocol = "udp"
		case *layers.SCTP:
			out.Port = uint16(layer.DstPort)
			out.Protocol = "sctp"
		default:
			if out.Protocol == "" {
				out.Protocol = strings.ToLower(transport.LayerType().String())
			}
		}
	}

	return out
}

// getEventTime returns the timestamp of the start of the window, or of the
// first packet in the batch or filtered batch, or the current time if no
// packets are available.
func getEventTime(
	windowStart time.Time,
	batch *[]gopacket.Packet,
) time.Time {
	eventTime := windowStart

	if eventTime.IsZero() {
		if batch != nil && len(*batch) > 0 {
			if md := (*batch)[0].Metadata(); md != nil {
				eventTime = md.Timestamp
			}
		} else {
			eventTime = time.Now()
		}
	}

	return eventTime
}
