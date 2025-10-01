package capture

import (
	"testing"
	"time"
)

func TestPacketSummary(t *testing.T) {
	summary := PacketSummary{
		Timestamp:  time.Now(),
		SourceIP:   "192.168.1.100",
		DestIP:     "8.8.8.8",
		SourcePort: "54321",
		DestPort:   "443",
		Protocol:   "TCP",
		Length:     64,
		Info:       "SYN ",
	}

	if summary.SourceIP != "192.168.1.100" {
		t.Errorf("Expected SourceIP 192.168.1.100, got %s", summary.SourceIP)
	}

	if summary.Protocol != "TCP" {
		t.Errorf("Expected Protocol TCP, got %s", summary.Protocol)
	}
}

func TestSessionCreation(t *testing.T) {
	// Test that GetCurrentSession returns nil when no session exists
	session := GetCurrentSession()
	if session != nil {
		t.Error("Expected no active session initially")
	}
}

func TestStatus(t *testing.T) {
	status := Status()
	if status != "No active capture" {
		t.Errorf("Expected 'No active capture', got %s", status)
	}
}

func TestStopCurrentSession(t *testing.T) {
	// Should error when no session exists
	err := StopCurrentSession()
	if err == nil {
		t.Error("Expected error when stopping non-existent session")
	}
}
