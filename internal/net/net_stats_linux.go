//go:build linux

package net

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// getExtendedInterfaceInfo returns speed and type
func getExtendedInterfaceInfo(name string) (speed string, ifaceType string, err error) {
	speed = "Unknown"
	ifaceType = "Unknown"

	// Check /sys/class/net/<name>/type (1=ethernet, etc)
	// For now just check speed
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "speed"))
	if err == nil {
		s := strings.TrimSpace(string(data))
		if _, err := strconv.Atoi(s); err == nil {
			speed = s + " Mbps"
		}
	}
	// TODO: better type detection
	ifaceType = "Ethernet"

	return speed, ifaceType, nil
}

// InterfaceStats holds interface statistics
type InterfaceStats struct {
	BytesRx   uint64
	BytesTx   uint64
	PacketsRx uint64
	PacketsTx uint64
}

// getInterfaceStats retrieves network statistics for an interface on Linux
func getInterfaceStats(name string) (*InterfaceStats, error) {
	stats := &InterfaceStats{}

	// Read from /sys/class/net/<interface>/statistics/
	basePath := filepath.Join("/sys/class/net", name, "statistics")

	// Read RX bytes
	if data, err := os.ReadFile(filepath.Join(basePath, "rx_bytes")); err == nil {
		if val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			stats.BytesRx = val
		}
	}

	// Read TX bytes
	if data, err := os.ReadFile(filepath.Join(basePath, "tx_bytes")); err == nil {
		if val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			stats.BytesTx = val
		}
	}

	// Read RX packets
	if data, err := os.ReadFile(filepath.Join(basePath, "rx_packets")); err == nil {
		if val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			stats.PacketsRx = val
		}
	}

	// Read TX packets
	if data, err := os.ReadFile(filepath.Join(basePath, "tx_packets")); err == nil {
		if val, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); err == nil {
			stats.PacketsTx = val
		}
	}

	return stats, nil
}
