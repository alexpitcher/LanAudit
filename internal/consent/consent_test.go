package consent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfirm(t *testing.T) {
	tests := []struct {
		name          string
		userInput     string
		requiredToken string
		wantErr       bool
	}{
		{"exact match", "VLAN-YES", "VLAN-YES", false},
		{"mismatch", "yes", "VLAN-YES", true},
		{"empty input", "", "VLAN-YES", true},
		{"whitespace", "  VLAN-YES  ", "VLAN-YES", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Confirm(tt.userInput, tt.requiredToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("Confirm() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLog(t *testing.T) {
	// Use temp directory for testing
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	action := "VLAN_CREATE"
	meta := map[string]string{
		"vlan":      "100",
		"interface": "en0",
	}

	err := Log(action, meta)
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	logPath := filepath.Join(tmpDir, ".lanaudit", ConsentLogFile)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	logContent := string(data)
	if !strings.Contains(logContent, action) {
		t.Errorf("log does not contain action '%s'", action)
	}

	if !strings.Contains(logContent, "vlan=100") {
		t.Error("log does not contain expected metadata")
	}

	if !strings.Contains(logContent, "interface=en0") {
		t.Error("log does not contain expected metadata")
	}
}

func TestLogMultipleEntries(t *testing.T) {
	tmpDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Log multiple entries
	Log("ACTION1", map[string]string{"key": "value1"})
	Log("ACTION2", map[string]string{"key": "value2"})

	logPath := filepath.Join(tmpDir, ".lanaudit", ConsentLogFile)
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Errorf("expected 2 log entries, got %d", len(lines))
	}
}
