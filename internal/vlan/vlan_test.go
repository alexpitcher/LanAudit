//go:build darwin

package vlan

import (
	"os"
	"testing"
)

func TestParseIPConfigPacket(t *testing.T) {
	data, err := os.ReadFile("testdata/ipconfig_getpacket.txt")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	result := &LeaseResult{VLAN: 100}
	parseIPConfigPacket(string(data), result)

	if result.IP != "192.168.100.50" {
		t.Errorf("IP = %s, want 192.168.100.50", result.IP)
	}

	if result.Router != "192.168.100.1" {
		t.Errorf("Router = %s, want 192.168.100.1", result.Router)
	}

	if len(result.DNS) < 1 {
		t.Errorf("expected at least 1 DNS server, got %d", len(result.DNS))
	} else if result.DNS[0] != "192.168.100.1" {
		t.Errorf("DNS[0] = %s, want 192.168.100.1", result.DNS[0])
	}

	if result.Err != "" {
		t.Errorf("unexpected error: %s", result.Err)
	}
}

func TestParseIPConfigPacketNoLease(t *testing.T) {
	result := &LeaseResult{VLAN: 100}
	parseIPConfigPacket("no valid data", result)

	if result.Err == "" {
		t.Error("expected error for no lease")
	}
}
