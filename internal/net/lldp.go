package net

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// LLDPNeighbor represents an LLDP neighbor device
type LLDPNeighbor struct {
	ChassisID      string
	ChassisIDType  string
	PortID         string
	PortIDType     string
	SystemName     string
	SystemDesc     string
	PortDesc       string
	ManagementAddr string
	Capabilities   []string
	TTL            uint16
	VLAN           int
	Discovered     time.Time
}

// DiscoverLLDP performs passive LLDP discovery on the specified interface
// Listens for LLDP packets for the specified duration
func DiscoverLLDP(iface string, duration time.Duration) ([]LLDPNeighbor, error) {
	// Open interface for passive capture
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w (requires sudo/root)", iface, err)
	}
	defer handle.Close()

	// Filter for LLDP packets (Ethernet type 0x88cc)
	if err := handle.SetBPFFilter("ether proto 0x88cc"); err != nil {
		return nil, fmt.Errorf("failed to set LLDP filter: %w", err)
	}

	neighbors := make(map[string]*LLDPNeighbor)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Set timeout for listening
	timeout := time.After(duration)
	packetChan := packetSource.Packets()

	for {
		select {
		case <-timeout:
			// Convert map to slice
			result := make([]LLDPNeighbor, 0, len(neighbors))
			for _, n := range neighbors {
				result = append(result, *n)
			}
			return result, nil

		case packet := <-packetChan:
			if packet == nil {
				continue
			}

			neighbor := parseLLDPPacket(packet)
			if neighbor != nil {
				// Use ChassisID + PortID as unique key
				key := fmt.Sprintf("%s:%s", neighbor.ChassisID, neighbor.PortID)
				neighbors[key] = neighbor
			}
		}
	}
}

// parseLLDPPacket extracts LLDP information from a packet
func parseLLDPPacket(packet gopacket.Packet) *LLDPNeighbor {
	neighbor := &LLDPNeighbor{
		Discovered: time.Now(),
	}

	// Check for LLDP layer
	if lldpLayer := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldpLayer != nil {
		lldp := lldpLayer.(*layers.LinkLayerDiscovery)

		// Parse Chassis ID
		neighbor.ChassisIDType = lldp.ChassisID.Subtype.String()
		neighbor.ChassisID = string(lldp.ChassisID.ID)
		if lldp.ChassisID.Subtype == layers.LLDPChassisIDSubTypeMACAddr {
			if len(lldp.ChassisID.ID) >= 6 {
				neighbor.ChassisID = net.HardwareAddr(lldp.ChassisID.ID).String()
			}
		}

		// Parse Port ID
		neighbor.PortIDType = lldp.PortID.Subtype.String()
		neighbor.PortID = string(lldp.PortID.ID)

		// Parse TTL
		neighbor.TTL = lldp.TTL

		// Parse optional TLVs
		// TLV types: 5=SysName, 6=SysDesc, 4=PortDesc, 7=SysCap, 8=MgmtAddr
		for _, tlv := range lldp.Values {
			switch tlv.Type {
			case 5: // System Name
				neighbor.SystemName = string(tlv.Value)
			case 6: // System Description
				neighbor.SystemDesc = string(tlv.Value)
			case 4: // Port Description
				neighbor.PortDesc = string(tlv.Value)
			case 8: // Management Address
				if len(tlv.Value) >= 6 {
					// Management address format: subtype + address
					addrLen := int(tlv.Value[0])
					if len(tlv.Value) >= 1+addrLen {
						addrSubtype := tlv.Value[1]
						addr := tlv.Value[2 : 2+addrLen-1]
						if addrSubtype == 1 && len(addr) == 4 {
							// IPv4
							neighbor.ManagementAddr = net.IP(addr).String()
						}
					}
				}
			case 7: // System Capabilities
				neighbor.Capabilities = parseCapabilities(tlv.Value)
			}
		}

		// Check for organization-specific TLVs (VLAN info, etc.)
		if info := packet.Layer(layers.LayerTypeLinkLayerDiscoveryInfo); info != nil {
			lldpInfo := info.(*layers.LinkLayerDiscoveryInfo)
			// Parse organization-specific info if available
			if lldpInfo.PortDescription != "" {
				neighbor.PortDesc = lldpInfo.PortDescription
			}
		}

		return neighbor
	}

	return nil
}

// parseCapabilities converts LLDP capability bits to string descriptions
func parseCapabilities(data []byte) []string {
	if len(data) < 4 {
		return nil
	}

	// Capabilities are a 16-bit bitmap
	caps := binary.BigEndian.Uint16(data[0:2])
	enabled := binary.BigEndian.Uint16(data[2:4])

	capMap := map[uint16]string{
		0x01: "Other",
		0x02: "Repeater",
		0x04: "Bridge",
		0x08: "WLAN AP",
		0x10: "Router",
		0x20: "Telephone",
		0x40: "DOCSIS",
		0x80: "Station",
	}

	result := make([]string, 0)
	for bit, name := range capMap {
		if caps&bit != 0 && enabled&bit != 0 {
			result = append(result, name)
		}
	}

	return result
}

// FormatLLDPNeighbor returns a human-readable string representation
func FormatLLDPNeighbor(n LLDPNeighbor) string {
	s := fmt.Sprintf("System: %s\n", n.SystemName)
	if n.SystemDesc != "" {
		s += fmt.Sprintf("  Description: %s\n", n.SystemDesc)
	}
	s += fmt.Sprintf("  Chassis ID: %s (%s)\n", n.ChassisID, n.ChassisIDType)
	s += fmt.Sprintf("  Port: %s (%s)\n", n.PortID, n.PortIDType)
	if n.PortDesc != "" {
		s += fmt.Sprintf("  Port Description: %s\n", n.PortDesc)
	}
	if n.ManagementAddr != "" {
		s += fmt.Sprintf("  Management IP: %s\n", n.ManagementAddr)
	}
	if len(n.Capabilities) > 0 {
		s += fmt.Sprintf("  Capabilities: %v\n", n.Capabilities)
	}
	if n.VLAN > 0 {
		s += fmt.Sprintf("  VLAN: %d\n", n.VLAN)
	}
	s += fmt.Sprintf("  TTL: %d seconds\n", n.TTL)

	return s
}
