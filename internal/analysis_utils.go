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

func mergeDestinationCounts(acc map[Destination]int, batch map[Destination]int) (map[Destination]int, int) {
	if len(batch) == 0 {
		return acc, 0
	}

	if acc == nil {
		acc = make(map[Destination]int, len(batch))
	}

	newDestinations := 0

	for destination, count := range batch {
		if count == 0 {
			continue
		}
		if _, exists := acc[destination]; !exists {
			newDestinations++
		}
		acc[destination] += count
	}

	return acc, newDestinations
}

// countPacketsByDestination tallies packets overall and per destination endpoint.
func countPacketsByDestination(
	pkts *[]gopacket.Packet,
	excludeIPs *[]string,
	maxDestinations int,
) (int, map[Destination]int, error) {
	if pkts == nil || len(*pkts) == 0 {
		return 0, nil, nil
	}

	hostCounts := make(map[Destination]int, maxDestinations)
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

		if len(hostCounts) < maxDestinations || hostCounts[destination] > 0 {
			hostCounts[destination]++
		} else {
			return total, hostCounts, &MaxDestinationsReached{}
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
