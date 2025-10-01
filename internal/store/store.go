package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/alexpitcher/LanAudit/internal/logging"
)

const (
	DefaultConfigDir = ".lanaudit"
	ConfigFile       = "config.json"
	SnapshotsDir     = "snaps"
	IndexFile        = "index.json"
)

var (
	ipPattern  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	macPattern = regexp.MustCompile(`\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b`)
)

// Config holds application configuration
type Config struct {
	DNSAlternates      []string      `json:"dns_alternates"`
	DiagnosticsTimeout int           `json:"diagnostics_timeout_ms"`
	Redact             bool          `json:"redact"`
	Console            ConsoleConfig `json:"console"`
}

// ConsoleConfig holds serial console settings
type ConsoleConfig struct {
	DefaultBauds           []int  `json:"default_bauds"`
	CRLFMode               string `json:"crlf_mode"`
	LocalEcho              bool   `json:"local_echo"`
	LogByDefault           bool   `json:"log_by_default"`
	BreakDurationMs        int    `json:"break_ms"`
	AllowProbeInConfigMode bool   `json:"allow_probe_in_config_mode"`
}

// Snapshot represents a point-in-time capture of network state
type Snapshot struct {
	Timestamp   time.Time        `json:"timestamp"`
	Hostname    string           `json:"hostname"`
	Interface   string           `json:"interface"`
	Details     interface{}      `json:"details"`
	Diagnostics interface{}      `json:"diagnostics,omitempty"`
	VLANResults interface{}      `json:"vlan_results,omitempty"`
	Console     *ConsoleSnapshot `json:"console,omitempty"`
	Settings    *Config          `json:"settings"`
	Redacted    bool             `json:"redacted"`
}

// ConsoleSnapshot captures console session summary
type ConsoleSnapshot struct {
	Port           string              `json:"port"`
	Baud           int                 `json:"baud"`
	Fingerprint    string              `json:"fingerprint,omitempty"`
	Detail         *ConsoleFingerprint `json:"console_fingerprint,omitempty"`
	BytesWritten   uint64              `json:"bytes_written"`
	BytesRead      uint64              `json:"bytes_read"`
	LogPath        string              `json:"log_path,omitempty"`
	TranscriptHead string              `json:"transcript_head,omitempty"` // First 2KB
	TranscriptTail string              `json:"transcript_tail,omitempty"` // Last 4KB
}

// ConsoleFingerprint captures structured identification data for the console target.
type ConsoleFingerprint struct {
	Vendor     string    `json:"vendor"`
	OS         string    `json:"os"`
	Model      string    `json:"model,omitempty"`
	Stage      string    `json:"stage"`
	Prompt     string    `json:"prompt,omitempty"`
	Baud       int       `json:"baud"`
	Confidence float64   `json:"confidence"`
	Evidence   []string  `json:"evidence,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// SnapshotIndex tracks all snapshots
type SnapshotIndex struct {
	Snapshots []SnapshotSummary `json:"snapshots"`
}

// SnapshotSummary provides quick overview of a snapshot
type SnapshotSummary struct {
	Timestamp time.Time `json:"timestamp"`
	Filename  string    `json:"filename"`
	Interface string    `json:"interface"`
	Hostname  string    `json:"hostname"`
}

// GetConfigPath returns the full path to config file
func GetConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultConfigDir, ConfigFile), nil
}

// GetSnapshotsDir returns the snapshots directory path
func GetSnapshotsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultConfigDir, SnapshotsDir), nil
}

// LoadConfig loads configuration from disk
func LoadConfig() (*Config, error) {
	configPath, err := GetConfigPath()
	if err != nil {
		logging.Errorf("LoadConfig: failed to resolve path: %v", err)
		return nil, err
	}

	// Return defaults if config doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		logging.Warnf("LoadConfig: config missing, using defaults")
		return DefaultConfig(), nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		logging.Errorf("LoadConfig: read error: %v", err)
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		logging.Errorf("LoadConfig: parse error: %v", err)
		return nil, err
	}
	logging.Infof("LoadConfig: loaded settings from %s", configPath)

	return &config, nil
}

// SaveConfig saves configuration to disk
func SaveConfig(config *Config) error {
	configPath, err := GetConfigPath()
	if err != nil {
		return err
	}

	// Ensure directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		logging.Errorf("SaveConfig: marshal error: %v", err)
		return err
	}

	logging.Infof("SaveConfig: writing config to %s", configPath)
	return os.WriteFile(configPath, data, 0644)
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		DNSAlternates:      []string{"1.1.1.1", "8.8.8.8"},
		DiagnosticsTimeout: 1500,
		Redact:             false,
		Console: ConsoleConfig{
			DefaultBauds:           []int{9600, 115200},
			CRLFMode:               "CRLF",
			LocalEcho:              false,
			LogByDefault:           false,
			BreakDurationMs:        250,
			AllowProbeInConfigMode: false,
		},
	}
}

// SaveSnapshot saves a snapshot to disk
func SaveSnapshot(snap *Snapshot) (string, error) {
	snapsDir, err := GetSnapshotsDir()
	if err != nil {
		return "", err
	}

	// Ensure directory exists
	if err := os.MkdirAll(snapsDir, 0755); err != nil {
		return "", err
	}

	// Generate filename
	filename := fmt.Sprintf("%s.json", snap.Timestamp.Format("20060102-150405"))
	filepath := filepath.Join(snapsDir, filename)

	// Redact if requested
	if snap.Redacted {
		snap = redactSnapshot(snap)
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		logging.Errorf("SaveSnapshot: marshal error: %v", err)
		return "", err
	}

	if err := os.WriteFile(filepath, data, 0644); err != nil {
		logging.Errorf("SaveSnapshot: write error: %v", err)
		return "", err
	}
	logging.Infof("SaveSnapshot: wrote snapshot %s", filepath)

	// Update index
	if err := updateIndex(snap, filename); err != nil {
		return filepath, err
	}

	return filepath, nil
}

// updateIndex adds snapshot to index file
func updateIndex(snap *Snapshot, filename string) error {
	snapsDir, err := GetSnapshotsDir()
	if err != nil {
		return err
	}

	indexPath := filepath.Join(snapsDir, IndexFile)

	var index SnapshotIndex

	// Load existing index if it exists
	if data, err := os.ReadFile(indexPath); err == nil {
		json.Unmarshal(data, &index)
	}

	// Add new entry
	index.Snapshots = append(index.Snapshots, SnapshotSummary{
		Timestamp: snap.Timestamp,
		Filename:  filename,
		Interface: snap.Interface,
		Hostname:  snap.Hostname,
	})
	logging.Debugf("updateIndex: added snapshot %s", filename)

	// Save index
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(indexPath, data, 0644); err != nil {
		return err
	}
	logging.Debugf("updateIndex: wrote index %s", indexPath)
	return nil
}

// redactSnapshot anonymizes sensitive data
func redactSnapshot(snap *Snapshot) *Snapshot {
	// Create a deep copy to avoid modifying original
	redacted := *snap
	logging.Debugf("redactSnapshot: start for %s", snap.Hostname)

	// Redact would process the details/diagnostics to mask IP octets and MAC addresses
	// For now, we set a flag indicating redaction was applied
	redacted.Redacted = true

	if snap.Console != nil {
		consoleCopy := *snap.Console
		consoleCopy.Fingerprint = scrubSensitive(consoleCopy.Fingerprint)

		if snap.Console.Detail != nil {
			detailCopy := *snap.Console.Detail
			detailCopy.Model = scrubSensitive(detailCopy.Model)
			detailCopy.Prompt = scrubSensitive(detailCopy.Prompt)
			detailCopy.Evidence = redactEvidence(detailCopy.Evidence)
			consoleCopy.Detail = &detailCopy
		}

		redacted.Console = &consoleCopy
	}

	return &redacted
}

func scrubSensitive(input string) string {
	if input == "" {
		return input
	}
	s := ipPattern.ReplaceAllString(input, "[REDACTED-IP]")
	s = macPattern.ReplaceAllString(s, "[REDACTED-MAC]")
	return s
}

func redactEvidence(lines []string) []string {
	if len(lines) == 0 {
		return lines
	}
	result := make([]string, len(lines))
	for i, line := range lines {
		result[i] = scrubSensitive(line)
	}
	return result
}

// RedactIP masks the last octet of an IP address
func RedactIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		parts[3] = "xxx"
		return strings.Join(parts, ".")
	}
	return ip
}

// RedactMAC masks parts of a MAC address
func RedactMAC(mac string) string {
	parts := strings.Split(mac, ":")
	if len(parts) == 6 {
		parts[4] = "xx"
		parts[5] = "xx"
		return strings.Join(parts, ":")
	}
	return mac
}
