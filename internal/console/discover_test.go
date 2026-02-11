package console

import (
	"testing"
)

func TestFilterBluetoothAndDebug(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"USB serial", "/dev/ttyUSB0", true},
		{"USB ACM", "/dev/ttyACM0", true},
		{"macOS cu", "/dev/cu.usbserial-XXXX", true},
		{"macOS tty", "/dev/tty.usbserial-XXXX", true},
		{"Bluetooth", "/dev/tty.Bluetooth-Incoming-Port", false},
		{"AirPods", "/dev/cu.AirPods-SPP", false},
		{"Wireless", "/dev/tty.wireless", false},
		{"Debug", "/dev/debug-console", false},
		{"WLAN", "/dev/wlan0", false},
		{"rfcomm", "/dev/rfcomm0", false},
		{"hci", "/dev/hci0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterBluetoothAndDebug(tt.path)
			if got != tt.want {
				t.Errorf("FilterBluetoothAndDebug(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestGenerateFriendlyName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/dev/ttyUSB0", "ttyUSB0"}, // Returns basename on macOS
		{"/dev/ttyACM1", "ttyACM1"},
		{"/dev/ttyS0", "ttyS0"},
		{"/dev/cu.usbserial-FT123456", "usbserial-FT123456"},
		{"/dev/tty.usbmodem12345", "usbmodem12345"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := generateFriendlyName(tt.path)
			if got != tt.want {
				t.Errorf("generateFriendlyName(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectHints(t *testing.T) {
	tests := []struct {
		path      string
		wantHints string
	}{
		{"/dev/ttyUSB-ftdi", "FTDI"},
		{"/dev/cu.usbserial-cp2102", "CP210x, USB-Serial"},
		{"/dev/tty.usbmodem-ch340", "CH34x, USB-Modem"},
		{"/dev/ttyACM0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := detectHints(tt.path)
			if got != tt.wantHints {
				t.Errorf("detectHints(%q) = %q, want %q", tt.path, got, tt.wantHints)
			}
		})
	}
}

func TestDiscoverPorts(t *testing.T) {
	// This will return real ports or empty list
	ports, err := DiscoverPorts()
	if err != nil {
		t.Fatalf("DiscoverPorts() error = %v", err)
	}

	// Just verify structure is correct
	for i, port := range ports {
		if port.Path == "" {
			t.Errorf("Port %d has empty path", i)
		}
		if port.FriendlyName == "" {
			t.Errorf("Port %d has empty friendly name", i)
		}
	}
}
