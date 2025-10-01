//go:build darwin

package net

import (
	"os/exec"
	"regexp"
	"strconv"
)

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
