package capture

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// PacketSummary represents a captured packet
type PacketSummary struct {
	Timestamp  time.Time
	SourceIP   string
	DestIP     string
	SourcePort string
	DestPort   string
	Protocol   string
	Length     int
	Info       string
}

// Session represents an active capture session
type Session struct {
	Interface  string
	Handle     *pcap.Handle
	LinkType   layers.LinkType
	Packets    []PacketSummary
	RawPackets []gopacket.Packet
	mu         sync.RWMutex
	stopChan   chan struct{}
	running    bool
}

var (
	currentSession *Session
	sessionMu      sync.RWMutex
)

// Start begins packet capture on the specified interface
// Requires sudo/root privileges
func Start(iface string, filter string, maxPackets int) (*Session, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if currentSession != nil && currentSession.running {
		return nil, fmt.Errorf("capture session already running on %s", currentSession.Interface)
	}

	// Open device with timeout
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w (requires sudo/root)", iface, err)
	}

	// Apply BPF filter if provided
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("invalid filter: %w", err)
		}
	}

	session := &Session{
		Interface:  iface,
		Handle:     handle,
		LinkType:   handle.LinkType(),
		Packets:    make([]PacketSummary, 0, maxPackets),
		RawPackets: make([]gopacket.Packet, 0, maxPackets),
		stopChan:   make(chan struct{}),
		running:    true,
	}

	currentSession = session

	// Start capture goroutine
	go session.captureLoop(maxPackets)

	return session, nil
}

// captureLoop processes packets in the background
func (s *Session) captureLoop(maxPackets int) {
	packetSource := gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())

	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}

			summary := s.parsePacket(packet)

			s.mu.Lock()
			if len(s.Packets) >= maxPackets {
				s.mu.Unlock()
				s.Stop()
				return
			}
			s.Packets = append(s.Packets, summary)
			s.RawPackets = append(s.RawPackets, packet)
			s.mu.Unlock()
		}
	}
}

// parsePacket extracts summary information from a packet
func (s *Session) parsePacket(packet gopacket.Packet) PacketSummary {
	summary := PacketSummary{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	// Extract network layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		summary.SourceIP = ip.SrcIP.String()
		summary.DestIP = ip.DstIP.String()
		summary.Protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		summary.SourceIP = ip.SrcIP.String()
		summary.DestIP = ip.DstIP.String()
		summary.Protocol = ip.NextHeader.String()
	}

	// Extract transport layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		summary.SourcePort = fmt.Sprintf("%d", tcp.SrcPort)
		summary.DestPort = fmt.Sprintf("%d", tcp.DstPort)
		summary.Protocol = "TCP"

		// Add TCP flags info
		flags := ""
		if tcp.SYN {
			flags += "SYN "
		}
		if tcp.ACK {
			flags += "ACK "
		}
		if tcp.FIN {
			flags += "FIN "
		}
		if tcp.RST {
			flags += "RST "
		}
		summary.Info = flags
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		summary.SourcePort = fmt.Sprintf("%d", udp.SrcPort)
		summary.DestPort = fmt.Sprintf("%d", udp.DstPort)
		summary.Protocol = "UDP"
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		summary.Protocol = "ICMP"
		summary.Info = fmt.Sprintf("Type: %d", icmp.TypeCode.Type())
	}

	// Application layer hints
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		if summary.DestPort == "443" || summary.SourcePort == "443" {
			summary.Info += "TLS "
		} else if summary.DestPort == "80" || summary.SourcePort == "80" {
			summary.Info += "HTTP "
		} else if summary.DestPort == "53" || summary.SourcePort == "53" {
			summary.Info += "DNS "
		}
	}

	return summary
}

// Stop halts the current capture session
func (s *Session) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.stopChan)
	s.Handle.Close()
}

// GetPackets returns a copy of captured packets
func (s *Session) GetPackets() []PacketSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	packets := make([]PacketSummary, len(s.Packets))
	copy(packets, s.Packets)
	return packets
}

// GetPacketCount returns the current number of captured packets
func (s *Session) GetPacketCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Packets)
}

// IsRunning returns whether the session is currently capturing
func (s *Session) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetCurrentSession returns the active capture session if any
func GetCurrentSession() *Session {
	sessionMu.RLock()
	defer sessionMu.RUnlock()
	return currentSession
}

// StopCurrentSession stops the current session if running
func StopCurrentSession() error {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if currentSession == nil {
		return fmt.Errorf("no active capture session")
	}

	currentSession.Stop()
	// currentSession = nil // Keep session available for saving/inspection
	return nil
}

// Status returns information about the capture status
func Status() string {
	sessionMu.RLock()
	defer sessionMu.RUnlock()

	if currentSession == nil || !currentSession.running {
		return "No active capture"
	}

	return fmt.Sprintf("Capturing on %s: %d packets",
		currentSession.Interface,
		currentSession.GetPacketCount())
}

// SaveToPCAP saves the captured packets to a PCAP file
func (s *Session) SaveToPCAP(filename string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.RawPackets) == 0 {
		return fmt.Errorf("no packets to save")
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, s.LinkType); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	for _, p := range s.RawPackets {
		if err := w.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil {
			return fmt.Errorf("failed to write packet: %w", err)
		}
	}

	return nil
}
