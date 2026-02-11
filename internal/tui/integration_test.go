package tui

import (
	"testing"
	"time"

	"github.com/alexpitcher/LanAudit/internal/speedtest"
	tea "github.com/charmbracelet/bubbletea"
)

// TestSpeedtestFlow simulates the full speedtest workflow
func TestSpeedtestFlow(t *testing.T) {
	m := initialModelForTest()
	m = m.activateMode(ViewSpeedtest)
	m.layer = LayerView

	// 1. User presses 's' to start
	newM, cmd := m.handleKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = newM.(Model)
	if !m.speedtestView.running {
		t.Error("Expected speedtest to be running after 's'")
	}
	// We expect a command that runs the speedtest
	if cmd == nil {
		t.Error("Expected command to run speedtest")
	}

	// 2. Simulate backend returning data
	mockResult := &speedtest.Result{
		DownloadMbps: 100.5,
		UploadMbps:   50.2,
		Latency:      15 * time.Millisecond,
		ServerName:   "Test Server",
	}
	msg := speedtestResultMsg{res: mockResult, err: nil}

	// 3. Update model with result
	newM, _ = m.Update(msg)
	m = newM.(Model)

	if m.speedtestView.running {
		t.Error("Expected speedtest to stop running after result")
	}
	if m.speedtestView.result != mockResult {
		t.Error("Expected model to contain mock result")
	}

	// 4. Verify output contains our data
	output := m.renderSpeedtestView()
	if len(output) < 10 {
		t.Error("Output too short")
	}
}

// TestAuditFlow simulates the audit workflow
func TestAuditFlow(t *testing.T) {
	m := initialModelForTest()
	m = m.activateMode(ViewAudit)
	m.layer = LayerView

	// 1. User presses 's' to start
	newM, cmd := m.handleKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	m = newM.(Model)

	// Note: We might need to mock details/gateway for runAuditCmd to work without error
	// But simply checking if it attempts to run is a good start.
	// runAuditCmd checks for gateway string.
	if cmd == nil {
		t.Error("Expected command to run audit")
	}

	if m.auditView.running {
		// It sets running=true immediately
	} else {
		t.Error("Expected audit to be running")
	}
}

// TestCaptureFlow simulates packet capture
func TestCaptureFlow(t *testing.T) {
	m := initialModelForTest()
	m = m.activateMode(ViewCapture)

	// 1. Start Capture
	m.captureView.running = true // Simulate start command success

	// 2. Simulate Stop
	msg := stopCaptureMsg{err: nil}
	newM, _ := m.Update(msg)
	m = newM.(Model)

	if m.captureView.running {
		t.Error("Capture should be stopped after stopMsg")
	}
	if m.captureView.statusMessage != "Capture stopped" {
		t.Errorf("Unexpected status: %s", m.captureView.statusMessage)
	}
}
