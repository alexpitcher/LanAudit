package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// Mock objects and helpers for testing

func initialModelForTest() Model {
	return Model{
		mode:       ViewPicker,
		layer:      LayerInterface,
		interfaces: nil, // Mock interfaces if needed
		config:     nil, // Mock config if needed
	}
}

func TestNavigation(t *testing.T) {
	m := initialModelForTest()

	// Initial state
	if m.mode != ViewPicker {
		t.Errorf("Expected initial mode ViewPicker, got %v", m.mode)
	}
	if m.layer != LayerInterface {
		t.Errorf("Expected initial layer LayerInterface, got %v", m.layer)
	}

	// Test Esc from Interface layer -> Quit
	_, cmd := m.handleKeys(tea.KeyMsg{Type: tea.KeyEsc})
	if cmd == nil {
		t.Errorf("Expected Quit command on Esc from root, got nil")
	}
}

func TestModeSelection(t *testing.T) {
	m := initialModelForTest()
	// Simulate selecting an interface (mocking the selection logic requires more state)
	m.selectedIface = "en0"
	m.layer = LayerMode

	// Test navigating mode menu
	// Down
	newM, _ := m.handleKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	m = newM.(Model)
	if m.modeIndex != 1 {
		t.Errorf("Expected modeIndex 1 after 'j', got %d", m.modeIndex)
	}
	// Up
	newM, _ = m.handleKeys(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	m = newM.(Model)
	if m.modeIndex != 0 {
		t.Errorf("Expected modeIndex 0 after 'k', got %d", m.modeIndex)
	}
}

func TestRenderLLDPView(t *testing.T) {
	m := initialModelForTest()
	// Test uninitialized view
	out := m.renderLLDPView()
	if out != "LLDP view not initialized" {
		t.Errorf("Expected 'LLDP view not initialized', got %q", out)
	}

	// Test initialized empty view
	m.lldpView = &LLDPView{
		statusMessage: "Test status",
	}
	out = m.renderLLDPView()
	if !strings.Contains(out, "Test status") {
		t.Errorf("Output should contain status message")
	}
	if !strings.Contains(out, "No neighbors found") {
		t.Errorf("Output should indicate no neighbors")
	}
}
