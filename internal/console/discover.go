package console

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"go.bug.st/serial"
)

// SerialPort represents a discovered serial port
type SerialPort struct {
	Path         string
	FriendlyName string
	Hints        string
	VID          string
	PID          string
}

// DiscoverPorts enumerates available serial ports excluding Bluetooth and debug devices
func DiscoverPorts() ([]SerialPort, error) {
	// Get raw port list from serial library
	portsList, err := serial.GetPortsList()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate ports: %w", err)
	}

	ports := make([]SerialPort, 0)

	for _, path := range portsList {
		// Filter out Bluetooth and debug devices
		if !FilterBluetoothAndDebug(path) {
			continue
		}

		port := SerialPort{
			Path:         path,
			FriendlyName: generateFriendlyName(path),
			Hints:        detectHints(path),
		}

		ports = append(ports, port)
	}

	return ports, nil
}

// FilterBluetoothAndDebug returns true if the port should be included (not BT/debug)
func FilterBluetoothAndDebug(path string) bool {
	lower := strings.ToLower(path)

	// Exclude Bluetooth devices
	bluetoothPatterns := []string{
		"bluetooth",
		"airpods",
		"wireless",
		"wlan",
		"rfcomm",
		"hci",
	}

	for _, pattern := range bluetoothPatterns {
		if strings.Contains(lower, pattern) {
			return false
		}
	}

	// Exclude debug/kernel consoles
	debugPatterns := []string{
		"debug",
		"console",
	}

	for _, pattern := range debugPatterns {
		if strings.Contains(lower, pattern) {
			return false
		}
	}

	// Platform-specific filtering
	switch runtime.GOOS {
	case "darwin":
		// On macOS, prefer cu.* over tty.* for output
		// But include both if they pass filters
		return true

	case "linux":
		// Only include known good prefixes
		if strings.HasPrefix(lower, "/dev/ttyusb") ||
			strings.HasPrefix(lower, "/dev/ttyacm") ||
			strings.HasPrefix(lower, "/dev/ttys") {
			return true
		}
		// Exclude everything else
		return false

	default:
		return true
	}
}

// generateFriendlyName creates a human-readable name for the port
func generateFriendlyName(path string) string {
	base := filepath.Base(path)

	switch runtime.GOOS {
	case "darwin":
		// macOS: tty.usbserial-XXXX or cu.usbserial-XXXX
		if strings.HasPrefix(base, "tty.") {
			return strings.TrimPrefix(base, "tty.")
		}
		if strings.HasPrefix(base, "cu.") {
			return strings.TrimPrefix(base, "cu.")
		}
		return base

	case "linux":
		// Linux: ttyUSB0, ttyACM0, etc.
		if strings.HasPrefix(base, "ttyUSB") {
			return fmt.Sprintf("USB Serial %s", strings.TrimPrefix(base, "ttyUSB"))
		}
		if strings.HasPrefix(base, "ttyACM") {
			return fmt.Sprintf("USB ACM %s", strings.TrimPrefix(base, "ttyACM"))
		}
		if strings.HasPrefix(base, "ttyS") {
			return fmt.Sprintf("Serial Port %s", strings.TrimPrefix(base, "ttyS"))
		}
		return base

	default:
		return base
	}
}

// detectHints provides additional information about the device
func detectHints(path string) string {
	base := filepath.Base(path)
	lower := strings.ToLower(base)

	hints := make([]string, 0)

	// USB-to-Serial chipset hints
	if strings.Contains(lower, "ftdi") {
		hints = append(hints, "FTDI")
	}
	if strings.Contains(lower, "cp210") {
		hints = append(hints, "CP210x")
	}
	if strings.Contains(lower, "ch34") {
		hints = append(hints, "CH34x")
	}
	if strings.Contains(lower, "pl2303") {
		hints = append(hints, "Prolific")
	}

	// Device type hints
	if strings.Contains(lower, "usbserial") {
		hints = append(hints, "USB-Serial")
	}
	if strings.Contains(lower, "usbmodem") {
		hints = append(hints, "USB-Modem")
	}

	if len(hints) == 0 {
		return ""
	}

	return strings.Join(hints, ", ")
}

// GetPortDetails attempts to retrieve additional USB details for a port
func GetPortDetails(path string) (vid, pid, product string) {
	// The go.bug.st/serial library doesn't expose USB details directly
	// This would require platform-specific USB enumeration
	// For now, return empty strings
	// Future: could use sysfs on Linux or IOKit on macOS
	return "", "", ""
}
