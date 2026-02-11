package net

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func TestLLDPNeighbor(t *testing.T) {
	neighbor := LLDPNeighbor{
		ChassisID:      "00:11:22:33:44:55",
		ChassisIDType:  "MAC Address",
		PortID:         "GigabitEthernet1/0/1",
		PortIDType:     "Interface Name",
		SystemName:     "switch-01",
		SystemDesc:     "Cisco IOS Switch",
		PortDesc:       "Connected to server-01",
		ManagementAddr: "192.168.1.1",
		Capabilities:   []string{"Bridge", "Router"},
		TTL:            120,
		VLAN:           100,
		Discovered:     time.Now(),
	}

	if neighbor.SystemName != "switch-01" {
		t.Errorf("Expected SystemName 'switch-01', got %s", neighbor.SystemName)
	}

	if neighbor.TTL != 120 {
		t.Errorf("Expected TTL 120, got %d", neighbor.TTL)
	}

	if len(neighbor.Capabilities) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(neighbor.Capabilities))
	}
}

func TestParseCapabilities(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{
			name: "router and bridge",
			data: []byte{0x00, 0x14, 0x00, 0x14}, // Bridge (0x04) + Router (0x10) enabled
			want: []string{"Bridge", "Router"},
		},
		{
			name: "empty capabilities",
			data: []byte{0x00, 0x00, 0x00, 0x00},
			want: []string{},
		},
		{
			name: "invalid data",
			data: []byte{0x00},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCapabilities(tt.data)

			if tt.want == nil && got != nil {
				t.Errorf("parseCapabilities() = %v, want nil", got)
				return
			}

			if tt.want != nil && got == nil {
				t.Errorf("parseCapabilities() = nil, want %v", tt.want)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("parseCapabilities() returned %d items, want %d", len(got), len(tt.want))
			}
		})
	}
}

func TestFormatLLDPNeighbor(t *testing.T) {
	neighbor := LLDPNeighbor{
		ChassisID:      "00:11:22:33:44:55",
		ChassisIDType:  "MAC Address",
		PortID:         "Gi1/0/1",
		PortIDType:     "Interface Name",
		SystemName:     "test-switch",
		SystemDesc:     "Test Switch Description",
		PortDesc:       "Test Port",
		ManagementAddr: "192.168.1.1",
		Capabilities:   []string{"Bridge"},
		TTL:            120,
		VLAN:           100,
		Discovered:     time.Now(),
	}

	formatted := FormatLLDPNeighbor(neighbor)

	if formatted == "" {
		t.Error("FormatLLDPNeighbor() returned empty string")
	}

	// Check that key information is present
	if !strings.Contains(formatted, "test-switch") {
		t.Error("Formatted output should contain system name")
	}

	if !strings.Contains(formatted, "00:11:22:33:44:55") {
		t.Error("Formatted output should contain chassis ID")
	}
}

func TestParseCapabilitiesEncoding(t *testing.T) {
	// Test that capabilities are properly encoded/decoded
	data := make([]byte, 4)

	// Set Bridge (0x04) and Router (0x10) in both caps and enabled
	caps := uint16(0x14) // Binary: 00010100
	enabled := uint16(0x14)

	binary.BigEndian.PutUint16(data[0:2], caps)
	binary.BigEndian.PutUint16(data[2:4], enabled)

	result := parseCapabilities(data)

	if len(result) < 1 {
		t.Error("Expected at least one capability to be parsed")
	}

	// Should contain Bridge or Router
	foundBridge := false
	foundRouter := false
	for _, cap := range result {
		if cap == "Bridge" {
			foundBridge = true
		}
		if cap == "Router" {
			foundRouter = true
		}
	}

	if !foundBridge || !foundRouter {
		t.Errorf("Expected Bridge and Router capabilities, got %v", result)
	}
}
