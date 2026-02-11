//go:build darwin

package net

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// systemProfilerData matches the structure of system_profiler -json SPAirPortDataType output
type systemProfilerData struct {
	SPAirPortDataType []struct {
		SPAirportInterfaces []struct {
			Name           string `json:"_name"`
			CurrentNetwork *struct {
				TransmitRate int `json:"spairport_network_rate"`
			} `json:"spairport_current_network_information"`
			CardType string `json:"spairport_card_type"`
		} `json:"spairport_airport_interfaces"`
	} `json:"SPAirPortDataType"`
}

// getExtendedInterfaceInfo returns speed and type
func getExtendedInterfaceInfo(name string) (speed string, ifaceType string, err error) {
	speed = "Unknown"
	ifaceType = "Unknown"

	// 1. Try system_profiler for Wi-Fi interfaces (best for Wi-Fi tx rate)
	cmd := exec.Command("system_profiler", "-json", "SPAirPortDataType")
	output, err := cmd.Output()
	if err == nil {
		var data systemProfilerData
		if err := json.Unmarshal(output, &data); err == nil {
			for _, item := range data.SPAirPortDataType {
				for _, iface := range item.SPAirportInterfaces {
					if iface.Name == name {
						if iface.CardType == "Wi-Fi" {
							ifaceType = "Wi-Fi"
						}
						if iface.CurrentNetwork != nil && iface.CurrentNetwork.TransmitRate > 0 {
							speed = fmt.Sprintf("%d Mbps", iface.CurrentNetwork.TransmitRate)
						}
						return speed, ifaceType, nil
					}
				}
			}
		}
	}

	// 2. Try media options via networksetup (works for some ethernet adapters)
	// Note: networksetup -getmedia often returns "autoselect" which isn't a speed.
	// We already checked this in research and it wasn't very useful for negotiated speed.

	// 3. Fallback to ifconfig (sometimes shows media: ... 1000baseT ...)
	cmd = exec.Command("ifconfig", name)
	if output, err := cmd.Output(); err == nil {
		s := string(output)
		if strings.Contains(s, "ether") {
			ifaceType = "Ethernet"
		}
		// Look for "media: ... (1000baseT ...)"
		// This is a rough heuristic
		if strings.Contains(s, "1000baseT") {
			speed = "1000 Mbps"
		} else if strings.Contains(s, "100baseTX") {
			speed = "100 Mbps"
		} else if strings.Contains(s, "10baseT") {
			speed = "10 Mbps"
		} else if strings.Contains(s, "2500baseT") {
			speed = "2500 Mbps"
		} else if strings.Contains(s, "5000baseT") {
			speed = "5000 Mbps"
		} else if strings.Contains(s, "10GbaseT") {
			speed = "10 Gbps"
		}
	}

	return speed, ifaceType, nil
}

// InterfaceStats holds interface statistics
type InterfaceStats struct {
	BytesRx   uint64
	BytesTx   uint64
	PacketsRx uint64
	PacketsTx uint64
}

// getInterfaceStats retrieves network statistics for an interface on macOS
func getInterfaceStats(name string) (*InterfaceStats, error) {
	stats := &InterfaceStats{}

	// Use netstat -I to get interface stats
	cmd := exec.Command("netstat", "-I", name, "-b")
	output, err := cmd.Output()
	if err != nil {
		return stats, nil // Return empty stats if command fails
	}

	// Parse netstat output
	// Format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
	lines := regexp.MustCompile("\n").Split(string(output), -1)
	for _, line := range lines {
		if len(line) == 0 || line[0] == 'N' {
			continue
		}

		fields := regexp.MustCompile(`\s+`).Split(line, -1)
		if len(fields) >= 10 && fields[0] == name {
			// Ipkts (packets received)
			if val, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
				stats.PacketsRx = val
			}
			// Ibytes (bytes received)
			if val, err := strconv.ParseUint(fields[6], 10, 64); err == nil {
				stats.BytesRx = val
			}
			// Opkts (packets transmitted)
			if val, err := strconv.ParseUint(fields[7], 10, 64); err == nil {
				stats.PacketsTx = val
			}
			// Obytes (bytes transmitted)
			if val, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
				stats.BytesTx = val
			}
			break
		}
	}

	return stats, nil
}
