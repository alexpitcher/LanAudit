package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRedactIP(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.100", "192.168.1.xxx"},
		{"10.0.0.1", "10.0.0.xxx"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := RedactIP(tt.input); got != tt.want {
				t.Errorf("RedactIP(%s) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactMAC(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"00:11:22:33:44:55", "00:11:22:33:xx:xx"},
		{"a4:83:e7:12:34:56", "a4:83:e7:12:xx:xx"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := RedactMAC(tt.input); got != tt.want {
				t.Errorf("RedactMAC(%s) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestConfigRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	original := &Config{
		DNSAlternates:      []string{"1.1.1.1", "8.8.8.8"},
		DiagnosticsTimeout: 2000,
		Redact:             true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	loaded, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(loaded, &config); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	if config.DiagnosticsTimeout != original.DiagnosticsTimeout {
		t.Errorf("DiagnosticsTimeout = %d, want %d", config.DiagnosticsTimeout, original.DiagnosticsTimeout)
	}

	if config.Redact != original.Redact {
		t.Errorf("Redact = %v, want %v", config.Redact, original.Redact)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if len(config.DNSAlternates) == 0 {
		t.Error("expected default DNS alternates")
	}

	if config.DiagnosticsTimeout <= 0 {
		t.Error("expected positive diagnostics timeout")
	}
}

func TestSnapshotSerialization(t *testing.T) {
	snap := &Snapshot{
		Timestamp: time.Now(),
		Hostname:  "test-host",
		Interface: "en0",
		Details:   map[string]string{"ip": "192.168.1.100"},
		Settings:  DefaultConfig(),
		Redacted:  false,
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("failed to marshal snapshot: %v", err)
	}

	var loaded Snapshot
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal snapshot: %v", err)
	}

	if loaded.Hostname != snap.Hostname {
		t.Errorf("Hostname = %s, want %s", loaded.Hostname, snap.Hostname)
	}

	if loaded.Interface != snap.Interface {
		t.Errorf("Interface = %s, want %s", loaded.Interface, snap.Interface)
	}
}
