package tui

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/alexpitcher/LanAudit/internal/capture"
	fingerprint "github.com/alexpitcher/LanAudit/internal/console/fingerprint"
	"github.com/alexpitcher/LanAudit/internal/diagnostics"
	"github.com/alexpitcher/LanAudit/internal/logging"
	netpkg "github.com/alexpitcher/LanAudit/internal/net"
	"github.com/alexpitcher/LanAudit/internal/scan"
	"github.com/alexpitcher/LanAudit/internal/speedtest"
	"github.com/alexpitcher/LanAudit/internal/store"
	"github.com/alexpitcher/LanAudit/internal/vlan"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ViewMode represents the current view
type ViewMode int

const (
	ViewPicker ViewMode = iota
	ViewDetails
	ViewDiagnose
	ViewVLAN
	ViewSnap
	ViewSettings
	ViewCapture
	ViewAudit
	ViewSpeedtest
	ViewConsole
)

// Model is the main TUI model
type Model struct {
	mode          ViewMode
	selectedIface string
	interfaces    []netpkg.Iface
	// Menu state
	selectedIndex int // cursor for interface picker
	modeIndex     int // cursor for mode selection
	layer         MenuLayer
	config        *store.Config
	details       *netpkg.InterfaceDetails
	statusMsg     string
	width         int
	height        int
	err           error

	// Shared runtime state
	captureSession *capture.Session
	captureFilter  string
	inputActive    bool
	inputPrompt    string
	inputValue     string
	inputSubmit    func(*Model, string) tea.Cmd

	// Sub-models for each view
	detailsView   *DetailsView
	diagnoseView  *DiagnoseView
	vlanView      *VLANView
	snapView      *SnapView
	settingsView  *SettingsView
	captureView   *CaptureView
	auditView     *AuditView
	speedtestView *SpeedtestView
	lldpView      *LLDPView
	consoleView   *ConsoleView
}

// DetailsView handles the details tab
type DetailsView struct {
	details     *netpkg.InterfaceDetails
	lastUpdate  time.Time
	autoRefresh bool
}

// DiagnoseView handles the diagnostics tab
type DiagnoseView struct {
	running       bool
	result        *diagnostics.Result
	lastRun       time.Time
	err           error
	statusMessage string
}

// VLANView handles the VLAN tester tab
type VLANView struct {
	running       bool
	results       []vlan.LeaseResult
	statusMessage string
	err           error
	vlans         []int
	keep          bool
	consentToken  string
}

// SnapView handles snapshots
type SnapView struct {
	running       bool
	lastSnapshot  string
	statusMessage string
	err           error
}

// SettingsView handles settings
type SettingsView struct {
	config *store.Config
}

// CaptureView handles packet capture
type CaptureView struct {
	running       bool
	filter        string
	statusMessage string
}

// AuditView handles gateway audit
type AuditView struct {
	running       bool
	result        *scan.ScanResult
	err           error
	statusMessage string
	consentToken  string
}

// SpeedtestView handles speedtest
type SpeedtestView struct {
	running       bool
	result        *speedtest.Result
	err           error
	statusMessage string
	lastRun       time.Time
}

// LLDPView handles LLDP discovery
type LLDPView struct {
	running       bool
	neighbors     []netpkg.LLDPNeighbor
	err           error
	statusMessage string
	duration      time.Duration
}

// ConsoleView handles serial console
type ConsoleView struct {
	ports                  []interface{} // Serial ports
	selectedPort           int
	session                interface{} // Active session
	buffer                 []string    // Console output buffer
	statusMessage          string
	dtrState               bool
	rtsState               bool
	logging                bool
	fingerprint            *fingerprint.Result
	allowProbeInConfigMode bool
	probeStatus            string
}

type tickMsg time.Time

type diagnoseResultMsg struct {
	res *diagnostics.Result
	err error
}

type speedtestResultMsg struct {
	res *speedtest.Result
	err error
}

type vlanResultMsg struct {
	results []vlan.LeaseResult
	err     error
}

type auditResultMsg struct {
	result *scan.ScanResult
	err    error
}

type lldpResultMsg struct {
	neighbors []netpkg.LLDPNeighbor
	err       error
}

type snapshotResultMsg struct {
	path string
	err  error
}

// MenuLayer represents which layer of the UI is active
type MenuLayer int

const (
	LayerInterface MenuLayer = iota // pick interface
	LayerMode                       // pick mode
	LayerView                       // active view
)

// Init initializes the TUI
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		tick(),
	)
}

func tick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update handles messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	logging.Debugf("tui update received message: %T", msg)
	switch msg := msg.(type) {
	case tea.KeyMsg:
		logging.Infof("key pressed: %q (layer=%d mode=%d)", msg.String(), m.layer, m.mode)
		return m.handleKeys(msg)

	case diagnoseResultMsg:
		if m.diagnoseView == nil {
			m.diagnoseView = &DiagnoseView{}
		}
		m.diagnoseView.running = false
		m.diagnoseView.lastRun = time.Now()
		m.diagnoseView.result = msg.res
		m.diagnoseView.err = msg.err
		if msg.err != nil {
			m.diagnoseView.statusMessage = fmt.Sprintf("Diagnostics failed: %v", msg.err)
			logging.Warnf(m.diagnoseView.statusMessage)
		} else {
			m.diagnoseView.statusMessage = "Diagnostics complete"
			logging.Infof("Diagnostics completed successfully")
		}
		m.statusMsg = m.diagnoseView.statusMessage
		return m, nil

	case speedtestResultMsg:
		if m.speedtestView == nil {
			m.speedtestView = &SpeedtestView{}
		}
		m.speedtestView.running = false
		m.speedtestView.lastRun = time.Now()
		m.speedtestView.result = msg.res
		m.speedtestView.err = msg.err
		if msg.err != nil {
			m.speedtestView.statusMessage = fmt.Sprintf("Speedtest failed: %v", msg.err)
			logging.Warnf(m.speedtestView.statusMessage)
		} else {
			m.speedtestView.statusMessage = "Speedtest complete"
			logging.Infof("Speedtest completed successfully")
		}
		m.statusMsg = m.speedtestView.statusMessage
		return m, nil

	case tea.WindowSizeMsg:
		logging.Infof("window resize: %dx%d", msg.Width, msg.Height)
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		logging.Debugf("tick message: %v", time.Time(msg))
		// Auto-refresh details view if active
		if m.mode == ViewDetails && m.selectedIface != "" {
			details, err := netpkg.GetInterfaceDetails(m.selectedIface)
			if err == nil {
				m.details = details
				if m.detailsView != nil {
					m.detailsView.details = details
					m.detailsView.lastUpdate = time.Now()
					logging.Debugf("auto-refreshed details for %s", m.selectedIface)
				}
			} else {
				logging.Warnf("failed to refresh interface details: %v", err)
			}
		}
		return m, tick()

	case error:
		logging.Errorf("tui received error: %v", msg)
		m.err = msg
		return m, nil
	}

	return m, nil
}

// handleKeys processes keyboard input
func (m Model) handleKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		logging.Infof("key ctrl+c -> quit")
		return m, tea.Quit

	case "esc", "q":
		// Step back a layer; quit if at top
		logging.Infof("key %q -> back navigation (layer=%d)", msg.String(), m.layer)
		switch m.layer {
		case LayerView:
			m.layer = LayerMode
			m.statusMsg = "Select a mode"
			logging.Debugf("switched to mode selection layer")
			return m, nil
		case LayerMode:
			m.layer = LayerInterface
			m.statusMsg = "Select an interface"
			logging.Debugf("switched to interface selection layer")
			return m, nil
		default:
			logging.Infof("exit triggered by key %q", msg.String())
			return m, tea.Quit
		}

	case "d":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewDetails)
			m.layer = LayerView
			m.statusMsg = "Viewing Details"
			logging.Infof("key 'd' -> ViewDetails (%s)", m.selectedIface)
		}

	case "g":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewDiagnose)
			m.layer = LayerView
			m.statusMsg = "Viewing Diagnostics"
			logging.Infof("key 'g' -> ViewDiagnose (%s)", m.selectedIface)
		}

	case "v":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewVLAN)
			m.layer = LayerView
			m.statusMsg = "VLAN Tester"
			logging.Infof("key 'v' -> ViewVLAN (%s)", m.selectedIface)
		}

	case "n":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewSnap)
			m.layer = LayerView
			m.statusMsg = "Snapshots"
			logging.Infof("key 'n' -> ViewSnap (%s)", m.selectedIface)
		}

	case "r":
		if m.mode == ViewDiagnose && m.layer == LayerView {
			if m.selectedIface == "" {
				m.statusMsg = "Select an interface before running diagnostics"
				logging.Warnf(m.statusMsg)
				break
			}
			if m.diagnoseView == nil {
				m.diagnoseView = &DiagnoseView{}
			}
			if m.diagnoseView.running {
				logging.Debugf("diagnostics already running")
				break
			}
			m.diagnoseView.running = true
			m.diagnoseView.result = nil
			m.diagnoseView.err = nil
			m.diagnoseView.statusMessage = "Running diagnostics..."
			m.statusMsg = m.diagnoseView.statusMessage
			logging.Infof("starting diagnostics for %s", m.selectedIface)
			var timeout time.Duration
			if m.config != nil && m.config.DiagnosticsTimeout > 0 {
				timeout = time.Duration(m.config.DiagnosticsTimeout) * time.Millisecond
			}
			return m, runDiagnosticsCmd(m.selectedIface, timeout, m.config)
		}

	case "s":
		if m.mode == ViewSpeedtest && m.layer == LayerView {
			if m.speedtestView == nil {
				m.speedtestView = &SpeedtestView{}
			}
			if m.speedtestView.running {
				logging.Debugf("speedtest already running")
				break
			}
			m.speedtestView.running = true
			m.speedtestView.result = nil
			m.speedtestView.err = nil
			m.speedtestView.statusMessage = "Starting speedtest..."
			m.statusMsg = m.speedtestView.statusMessage
			logging.Infof("starting speedtest")
			return m, runSpeedtestCmd()
		}
		if m.layer == LayerView {
			break
		}
		m = m.activateMode(ViewSettings)
		m.layer = LayerView
		m.statusMsg = "Settings"
		logging.Infof("key 's' -> ViewSettings")

	case "c":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewCapture)
			m.layer = LayerView
			if m.captureView == nil {
				m.captureView = &CaptureView{
					statusMessage: "Packet capture ready. Press 's' to start, 'x' to stop.",
				}
				logging.Debugf("initialised capture view")
			}
			m.statusMsg = "Packet Capture"
			logging.Infof("key 'c' -> ViewCapture (%s)", m.selectedIface)
		}

	case "a":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewAudit)
			m.layer = LayerView
			if m.auditView == nil {
				m.auditView = &AuditView{
					statusMessage: "Gateway audit requires SCAN-YES consent.",
				}
				logging.Debugf("initialised audit view")
			}
			m.statusMsg = "Gateway Audit"
			logging.Infof("key 'a' -> ViewAudit (%s)", m.selectedIface)
		}

	case "p":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewSpeedtest)
			m.layer = LayerView
			if m.speedtestView == nil {
				m.speedtestView = &SpeedtestView{
					statusMessage: "Press 's' to start speedtest.",
				}
				logging.Debugf("initialised speedtest view")
			}
			m.statusMsg = "Speedtest"
			logging.Infof("key 'p' -> ViewSpeedtest (%s)", m.selectedIface)
		}

	case "l":
		if m.layer == LayerView {
			break
		}
		if m.selectedIface != "" {
			m = m.activateMode(ViewCapture) // Reuse capture mode for LLDP
			m.layer = LayerView
			if m.lldpView == nil {
				m.lldpView = &LLDPView{
					statusMessage: "LLDP discovery ready. Press 's' to scan for 30 seconds.",
				}
				logging.Debugf("initialised LLDP view")
			}
			m.statusMsg = "LLDP Discovery"
			logging.Infof("key 'l' -> LLDP (%s)", m.selectedIface)
		}

	case "o":
		if m.layer == LayerView && m.mode != ViewConsole {
			break
		}
		// Console doesn't require interface selection
		m = m.activateMode(ViewConsole)
		m.layer = LayerView
		if m.consoleView == nil {
			m.consoleView = &ConsoleView{
				ports:                  make([]interface{}, 0),
				selectedPort:           -1,
				buffer:                 make([]string, 0),
				statusMessage:          "Discovering serial ports...",
				dtrState:               true,
				rtsState:               true,
				logging:                false,
				allowProbeInConfigMode: m.config != nil && m.config.Console.AllowProbeInConfigMode,
			}
		}
		m.statusMsg = "Serial Console"
		logging.Infof("key 'o' -> ViewConsole")

	case "P":
		if m.mode == ViewConsole && m.consoleView != nil {
			m.consoleView.probeStatus = "Safe probe requested"
			m.statusMsg = "Safe probe requested"
			logging.Infof("console safe probe requested")
		}

	case "A":
		if m.mode == ViewConsole && m.consoleView != nil {
			m.consoleView.allowProbeInConfigMode = !m.consoleView.allowProbeInConfigMode
			if m.config != nil {
				m.config.Console.AllowProbeInConfigMode = m.consoleView.allowProbeInConfigMode
			}
			if m.consoleView.allowProbeInConfigMode {
				m.statusMsg = "Config-mode probes enabled"
				logging.Warnf("config-mode probes enabled by user")
			} else {
				m.statusMsg = "Config-mode probes disabled"
				logging.Infof("config-mode probes disabled by user")
			}
		}

	case "up", "k":
		if m.layer == LayerInterface {
			displayCount := len(m.interfaces)
			if displayCount > 8 {
				displayCount = 8
			}
			if displayCount > 0 {
				m.selectedIndex = (m.selectedIndex - 1 + displayCount) % displayCount
				logging.Debugf("interface cursor moved to index %d", m.selectedIndex)
			}
		} else if m.layer == LayerMode {
			// Move up in mode list
			modes := m.availableModes()
			if len(modes) > 0 {
				m.modeIndex = (m.modeIndex - 1 + len(modes)) % len(modes)
				logging.Debugf("mode cursor moved to index %d", m.modeIndex)
			}
		}

	case "down", "j":
		if m.layer == LayerInterface {
			displayCount := len(m.interfaces)
			if displayCount > 8 {
				displayCount = 8
			}
			if displayCount > 0 {
				m.selectedIndex = (m.selectedIndex + 1) % displayCount
				logging.Debugf("interface cursor moved to index %d", m.selectedIndex)
			}
		} else if m.layer == LayerMode {
			modes := m.availableModes()
			if len(modes) > 0 {
				m.modeIndex = (m.modeIndex + 1) % len(modes)
				logging.Debugf("mode cursor moved to index %d", m.modeIndex)
			}
		}

	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		if m.layer == LayerInterface {
			idx := int(msg.Runes[0]-'0') - 1
			displayCount := len(m.interfaces)
			if displayCount > 8 {
				displayCount = 8
			}
			if idx >= 0 && idx < displayCount {
				iface := m.interfaces[idx]
				m.selectedIface = iface.Name
				logging.Infof("digit %s -> interface %s", msg.String(), iface.Name)
				details, err := netpkg.GetInterfaceDetails(iface.Name)
				if err == nil {
					m.details = details
					m.detailsView = &DetailsView{
						details:     details,
						lastUpdate:  time.Now(),
						autoRefresh: true,
					}
					logging.Debugf("loaded details for %s", iface.Name)
				} else {
					logging.Warnf("failed to load details for %s: %v", iface.Name, err)
				}
				m.layer = LayerMode
				m.modeIndex = 0
				m.statusMsg = "Select a mode"
			}
		}

	case "enter":
		if m.layer == LayerInterface {
			// Select the currently highlighted interface
			displayCount := len(m.interfaces)
			if displayCount > 8 {
				displayCount = 8
			}
			if displayCount == 0 {
				break
			}
			if m.selectedIndex < 0 || m.selectedIndex >= displayCount {
				m.selectedIndex = 0
			}
			iface := m.interfaces[m.selectedIndex]
			m.selectedIface = iface.Name
			logging.Infof("enter -> interface %s", iface.Name)
			details, err := netpkg.GetInterfaceDetails(iface.Name)
			if err == nil {
				m.details = details
				m.detailsView = &DetailsView{
					details:     details,
					lastUpdate:  time.Now(),
					autoRefresh: true,
				}
				logging.Debugf("loaded details for %s", iface.Name)
			} else {
				logging.Warnf("failed to load details for %s: %v", iface.Name, err)
			}
			m.layer = LayerMode
			m.modeIndex = 0
			m.statusMsg = "Select a mode"
		} else if m.layer == LayerMode {
			modes := m.availableModes()
			if len(modes) == 0 {
				break
			}
			if m.modeIndex < 0 || m.modeIndex >= len(modes) {
				m.modeIndex = 0
			}
			sel := modes[m.modeIndex]
			m = m.activateMode(sel.mode)
			m.layer = LayerView
			logging.Infof("enter -> activate mode %v", sel.mode)
		}
	}

	return m, nil
}

// View renders the TUI
func (m Model) View() string {
	switch m.layer {
	case LayerInterface:
		return m.renderPicker()
	case LayerMode:
		return m.renderModeMenu()
	case LayerView:
		return lipgloss.JoinVertical(lipgloss.Left,
			m.renderContent(),
			m.renderStatus(),
		)
	default:
		return m.renderPicker()
	}
}

func (m Model) renderPicker() string {
	var s string
	s += "╔══════════════════════════════════════════════════════════════════╗\n"
	s += "║              LanAudit - Select Network Interface                 ║\n"
	s += "╠══════════════════════════════════════════════════════════════════╣\n"

	for i, iface := range m.interfaces {
		if i >= 8 {
			break
		}

		// Get IP address if available
		details, err := netpkg.GetInterfaceDetails(iface.Name)
		ipAddr := "(no IP address)"
		if err == nil && len(details.IPs) > 0 {
			// Show first non-link-local IPv4
			for _, ip := range details.IPs {
				if !strings.Contains(ip, ":") && !strings.HasPrefix(ip, "169.254.") {
					ipAddr = ip
					break
				}
			}
			if ipAddr == "(no IP address)" && len(details.IPs) > 0 {
				ipAddr = details.IPs[0]
			}
		}

		// Format stats
		rxMB := float64(iface.BytesRx) / 1024 / 1024
		txMB := float64(iface.BytesTx) / 1024 / 1024

		status := "UP  "
		if iface.Flags&net.FlagUp == 0 {
			status = "DOWN"
		}

		// Line 1: Number, name, status, IP (fixed width alignment)
		// Total width inside ║ ║ is 66 chars
		line1 := fmt.Sprintf("%d. %-8s [%s]  %s", i+1, iface.Name, status, ipAddr)
		marker := ' '
		if i == m.selectedIndex {
			marker = '>'
		}
		s += fmt.Sprintf("║ %c%-63s ║\n", marker, line1)

		// Line 2: Traffic stats (aligned)
		line2 := fmt.Sprintf("   RX: %8.1f MB  TX: %8.1f MB", rxMB, txMB)
		s += fmt.Sprintf("║  %-63s ║\n", line2)
	}

	s += "╠══════════════════════════════════════════════════════════════════╣\n"
	s += "║ Arrow keys: Navigate  |  1-9: Quick select  |  ENTER: Select   ║\n"
	s += "║ q/esc: Back/quit                                              ║\n"
	s += "╚══════════════════════════════════════════════════════════════════╝\n"

	return s
}

// availableModes returns the list of modes and labels used in the Mode menu
func (m Model) availableModes() []struct {
	label string
	mode  ViewMode
} {
	return []struct {
		label string
		mode  ViewMode
	}{
		{"[d] Details", ViewDetails},
		{"[g] Diagnose", ViewDiagnose},
		{"[v] VLAN", ViewVLAN},
		{"[n] Snap", ViewSnap},
		{"[s] Settings", ViewSettings},
		{"[c] Capture", ViewCapture},
		{"[a] Audit", ViewAudit},
		{"[p] Speedtest", ViewSpeedtest},
		{"[o] Console", ViewConsole},
	}
}

// renderModeMenu shows the list of modes to choose from
func (m Model) renderModeMenu() string {
	var s string
	s += "╔══════════════════════════════════════════════════════════════════╗\n"
	s += "║                      LanAudit - Select Mode                     ║\n"
	s += "╠══════════════════════════════════════════════════════════════════╣\n"

	modes := m.availableModes()
	for i, t := range modes {
		marker := ' '
		if i == m.modeIndex {
			marker = '>'
		}
		// strip the bracketed shortcut for cleaner display
		clean := t.label
		if strings.HasPrefix(clean, "[") {
			if idx := strings.Index(clean, "]"); idx != -1 && idx+1 < len(clean) {
				clean = strings.TrimSpace(clean[idx+1:])
			}
		}
		line := fmt.Sprintf("%d. %s", i+1, clean)
		s += fmt.Sprintf("║ %c%-63s ║\n", marker, line)
	}

	s += "╠══════════════════════════════════════════════════════════════════╣\n"
	s += "║ Arrow keys: Navigate  |  ENTER: Select  |  q/esc: Back          ║\n"
	s += "╚══════════════════════════════════════════════════════════════════╝\n"
	return s
}

// activateMode sets up and switches to a given view mode
func (m Model) activateMode(mode ViewMode) Model {
	m.mode = mode
	logging.Infof("activateMode -> %v", mode)
	switch mode {
	case ViewDetails:
		if m.selectedIface != "" {
			if m.details == nil || m.details.Name != m.selectedIface {
				if details, err := netpkg.GetInterfaceDetails(m.selectedIface); err == nil {
					m.details = details
				}
			}
			if m.details != nil {
				m.detailsView = &DetailsView{
					details:     m.details,
					lastUpdate:  time.Now(),
					autoRefresh: true,
				}
			}
		}
		m.statusMsg = "Viewing Details"

	case ViewDiagnose:
		m.statusMsg = "Viewing Diagnostics"

	case ViewVLAN:
		m.statusMsg = "VLAN Tester"

	case ViewSnap:
		m.statusMsg = "Snapshots"

	case ViewSettings:
		m.statusMsg = "Settings"

	case ViewCapture:
		if m.captureView == nil {
			m.captureView = &CaptureView{
				statusMessage: "Packet capture ready. Press 's' to start, 'x' to stop.",
			}
		}
		m.statusMsg = "Packet Capture"

	case ViewAudit:
		if m.auditView == nil {
			m.auditView = &AuditView{
				statusMessage: "Gateway audit requires SCAN-YES consent.",
			}
		}
		m.statusMsg = "Gateway Audit"

	case ViewSpeedtest:
		if m.speedtestView == nil {
			m.speedtestView = &SpeedtestView{
				statusMessage: "Press 's' to start speedtest.",
			}
		}
		m.statusMsg = "Speedtest"

	case ViewConsole:
		if m.consoleView == nil {
			m.consoleView = &ConsoleView{
				ports:         make([]interface{}, 0),
				selectedPort:  -1,
				buffer:        make([]string, 0),
				statusMessage: "Discovering serial ports...",
				dtrState:      true,
				rtsState:      true,
				logging:       false,
			}
		}
		m.statusMsg = "Serial Console"
	}
	return m
}

func (m Model) renderContent() string {
	switch m.mode {
	case ViewDetails:
		return m.renderDetailsView()
	case ViewDiagnose:
		return m.renderDiagnoseView()
	case ViewVLAN:
		return m.renderVLANView()
	case ViewSnap:
		return m.renderSnapView()
	case ViewSettings:
		return m.renderSettingsView()
	case ViewCapture:
		return m.renderCaptureView()
	case ViewAudit:
		return m.renderAuditView()
	case ViewSpeedtest:
		return m.renderSpeedtestView()
	case ViewConsole:
		return m.renderConsoleView()
	default:
		return "Unknown view"
	}
}

func (m Model) renderDetailsView() string {
	if m.details == nil {
		return "No interface selected"
	}

	var s string
	linkStatus := "DOWN"
	if m.details.LinkUp {
		linkStatus = "UP"
	}

	s += fmt.Sprintf("═══ Interface Details ═══\n\n")
	s += fmt.Sprintf("Interface:  %s\n", m.details.Name)
	s += fmt.Sprintf("MAC:        %s\n", m.details.MAC)
	s += fmt.Sprintf("MTU:        %d bytes\n", m.details.MTU)
	s += fmt.Sprintf("Link:       %s\n", linkStatus)
	s += fmt.Sprintf("Speed:      %s\n\n", m.details.Speed)

	s += "═══ IP Addresses ═══\n"
	if len(m.details.IPs) > 0 {
		for _, ip := range m.details.IPs {
			s += fmt.Sprintf("  %s\n", ip)
		}
	} else {
		s += "  No IP addresses configured\n"
	}

	s += fmt.Sprintf("\n═══ Network ═══\n")
	if m.details.DefaultGateway != "" {
		s += fmt.Sprintf("Gateway:    %s\n", m.details.DefaultGateway)
	} else {
		s += "Gateway:    Not configured\n"
	}

	s += "DNS Servers:\n"
	if len(m.details.DNSServers) > 0 {
		for _, dns := range m.details.DNSServers {
			s += fmt.Sprintf("  %s\n", dns)
		}
	} else {
		s += "  None configured\n"
	}

	s += fmt.Sprintf("\n═══ Traffic Statistics ═══\n")
	s += fmt.Sprintf("RX: %s (%s packets)\n",
		formatBytes(m.details.BytesRx),
		formatNumber(m.details.PacketsRx))
	s += fmt.Sprintf("TX: %s (%s packets)\n",
		formatBytes(m.details.BytesTx),
		formatNumber(m.details.PacketsTx))

	if m.detailsView != nil {
		s += fmt.Sprintf("\nLast updated: %s (auto-refresh every 2s)\n",
			m.detailsView.lastUpdate.Format("15:04:05"))
	}

	return s
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatNumber(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	} else if n < 1000000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	return fmt.Sprintf("%.1fG", float64(n)/1000000000)
}

func (m Model) renderDiagnoseView() string {
	var s strings.Builder
	s.WriteString("═══ Diagnostics ═══\n\n")

	if m.diagnoseView == nil {
		s.WriteString("Press 'r' to run diagnostics.\n")
		return s.String()
	}

	dv := m.diagnoseView
	status := dv.statusMessage
	if status == "" {
		status = "Press 'r' to run diagnostics."
	}
	s.WriteString(fmt.Sprintf("Status: %s\n\n", status))

	if dv.running {
		s.WriteString("Running tests...\n")
		return s.String()
	}

	if dv.err != nil {
		s.WriteString(fmt.Sprintf("Error: %v\n", dv.err))
		return s.String()
	}

	if dv.result == nil {
		s.WriteString("No diagnostics have been run yet.\n")
		return s.String()
	}

	res := dv.result
	s.WriteString(fmt.Sprintf("Link Up: %v\n", res.LinkUp))
	s.WriteString(fmt.Sprintf("Gateway: %s\n\n", res.Gateway))

	if res.Ping.Err != "" {
		s.WriteString(fmt.Sprintf("Ping: error %s\n", res.Ping.Err))
	} else {
		s.WriteString(fmt.Sprintf("Ping Loss: %.1f%%\n", res.Ping.Loss))
		s.WriteString(fmt.Sprintf("Ping RTT: %v\n", res.Ping.MedianRTT))
	}

	if res.DNS.Err != "" {
		s.WriteString(fmt.Sprintf("DNS Error: %s\n", res.DNS.Err))
	}
	s.WriteString(fmt.Sprintf("DNS System OK: %v\n", res.DNS.SystemOK))
	if len(res.DNS.AltTried) > 0 {
		s.WriteString(fmt.Sprintf("DNS Alternate OK: %v (tried %s)\n", res.DNS.AltOK, strings.Join(res.DNS.AltTried, ", ")))
	}

	if res.HTTPS.Err != "" {
		s.WriteString(fmt.Sprintf("HTTPS Error: %s\n", res.HTTPS.Err))
	} else {
		s.WriteString(fmt.Sprintf("HTTPS OK: %v (status %d)\n", res.HTTPS.OK, res.HTTPS.Status))
	}

	if len(res.Suggestions) > 0 {
		s.WriteString("\nSuggestions:\n")
		for _, suggestion := range res.Suggestions {
			s.WriteString(fmt.Sprintf("  - %s\n", suggestion))
		}
	}

	if !dv.lastRun.IsZero() {
		s.WriteString(fmt.Sprintf("\nLast run: %s\n", dv.lastRun.Format("15:04:05")))
	}

	return s.String()
}

func (m Model) renderVLANView() string {
	return "VLAN Tester\n\nThis feature requires root/sudo privileges.\n(Feature implementation in progress)"
}

func (m Model) renderSnapView() string {
	return "Snapshots\n\nPress 'n' to create a new snapshot\n(Feature implementation in progress)"
}

func (m Model) renderSettingsView() string {
	if m.config == nil {
		return "No configuration loaded"
	}

	var s string
	s += "Settings\n\n"
	s += fmt.Sprintf("DNS Alternates: %v\n", m.config.DNSAlternates)
	s += fmt.Sprintf("Diagnostics Timeout: %dms\n", m.config.DiagnosticsTimeout)
	s += fmt.Sprintf("Redact Mode: %v\n", m.config.Redact)
	return s
}

func (m Model) renderCaptureView() string {
	if m.captureView == nil {
		return "Capture view not initialized"
	}

	var s string
	s += "═══ Packet Capture ═══\n\n"
	s += fmt.Sprintf("Status: %s\n\n", m.captureView.statusMessage)

	if m.captureView.running {
		s += fmt.Sprintf("Packets captured: %d\n\n", m.captureView.packetCount)
		s += "Press 'x' to stop capture\n"
	} else {
		s += "Commands:\n"
		s += "  's' - Start capture (requires sudo/root)\n"
		s += "  'f' - Set BPF filter\n"
		s += "\nNote: Packet capture requires root privileges.\n"
	}

	return s
}

func (m Model) renderAuditView() string {
	if m.auditView == nil {
		return "Audit view not initialized"
	}

	var s string
	s += "═══ Gateway Audit ═══\n\n"
	s += fmt.Sprintf("Status: %s\n\n", m.auditView.statusMessage)

	if m.auditView.running {
		s += "Scanning network...\n"
	} else {
		s += "Gateway audit will scan the local subnet for active hosts\n"
		s += "and enumerate open ports on discovered devices.\n\n"
		s += "Commands:\n"
		s += "  's' - Start audit (requires SCAN-YES consent)\n"
		s += "\nNote: This is a network scanning tool. Use responsibly.\n"
	}

	return s
}

func (m Model) renderSpeedtestView() string {
	if m.speedtestView == nil {
		return "Speedtest view not initialized"
	}

	var s string
	s += "═══ Speedtest ═══\n\n"
	s += fmt.Sprintf("Status: %s\n\n", m.speedtestView.statusMessage)

	if m.speedtestView.running {
		s += "Running speedtest... This may take up to 30 seconds.\n"
		return s
	}

	if m.speedtestView.err != nil {
		s += fmt.Sprintf("Error: %v\n\n", m.speedtestView.err)
	}

	if m.speedtestView.result != nil {
		s += speedtest.FormatResult(m.speedtestView.result)
		s += "\n\nPress 's' to run again."
		if !m.speedtestView.lastRun.IsZero() {
			s += fmt.Sprintf("\nLast run: %s", m.speedtestView.lastRun.Format("15:04:05"))
		}
		return s
	}

	s += "Measure your internet connection speed using speedtest.net servers.\n\n"
	s += "Commands:\n"
	s += "  's' - Start speedtest\n"
	s += "\nTests download speed, upload speed, and latency.\n"

	return s
}

func (m Model) renderConsoleView() string {
	if m.consoleView == nil {
		return "Console view not initialized"
	}

	var s string
	s += "═══ Serial Console ═══\n\n"
	s += fmt.Sprintf("Status: %s\n\n", m.consoleView.statusMessage)

	if fp := m.consoleView.fingerprint; fp != nil {
		stage := formatStageLabel(fp.Stage)
		confidence := int(fp.Confidence*100 + 0.5)
		s += fmt.Sprintf("Fingerprint: %s / %s", fp.Vendor, fp.OS)
		if fp.Model != "" {
			s += fmt.Sprintf(" (%s)", fp.Model)
		}
		s += "\n"
		s += fmt.Sprintf("Stage: %s | Baud: %d | Confidence: %d%%\n", stage, fp.Baud, confidence)
		if fp.Prompt != "" {
			s += fmt.Sprintf("Prompt: %s\n", fp.Prompt)
		}
		if len(fp.Evidence) > 0 {
			s += "Evidence:\n"
			for _, ev := range fp.Evidence {
				s += fmt.Sprintf("  - %s\n", ev)
			}
		}
		if strings.Contains(strings.ToLower(fp.Prompt), "(config") && !m.consoleView.allowProbeInConfigMode {
			s += "⚠ Prompt appears to be configuration mode. Safe probes disabled until toggled.\n"
		}
		if m.consoleView.probeStatus != "" {
			s += fmt.Sprintf("Probe: %s\n", m.consoleView.probeStatus)
		}
		s += "\n"
	}

	if m.consoleView.session != nil {
		// Active session view
		s += "Console Output:\n"
		s += "───────────────────────────────────────────────────\n"

		// Show last 20 lines of buffer
		start := len(m.consoleView.buffer) - 20
		if start < 0 {
			start = 0
		}
		for i := start; i < len(m.consoleView.buffer); i++ {
			s += m.consoleView.buffer[i] + "\n"
		}

		s += "───────────────────────────────────────────────────\n\n"

		// Control status
		s += fmt.Sprintf("DTR: %v | RTS: %v | Logging: %v\n\n",
			m.consoleView.dtrState,
			m.consoleView.rtsState,
			m.consoleView.logging)

		s += "Commands:\n"
		s += "  'b' - Send BREAK  'd' - Toggle DTR  'r' - Toggle RTS\n"
		s += "  't' - Toggle logging  'x' - Close session\n"
		s += "  'P' - Run safe probe on current fingerprint\n"
		s += fmt.Sprintf("  '[%s]' Allow safe probe in config mode (press 'A')\n",
			boolMarker(m.consoleView.allowProbeInConfigMode))
	} else {
		// Port selection view
		s += "Discovered Serial Ports:\n"

		if len(m.consoleView.ports) == 0 {
			s += "\nNo serial ports found.\n"
			s += "\nPress 'f' to refresh port list\n"
		} else {
			s += "\n(Port discovery and selection placeholder)\n"
			s += "\nCommands:\n"
			s += "  'p' - Probe selected port\n"
			s += "  'enter' - Open session\n"
			s += "  'f' - Refresh ports\n"
			s += fmt.Sprintf("  '[%s]' Allow safe probe in config mode (press 'A')\n",
				boolMarker(m.consoleView.allowProbeInConfigMode))
		}
	}

	return s
}

func formatStageLabel(stage fingerprint.Stage) string {
	switch stage {
	case fingerprint.StagePreLogin:
		return "Pre-login"
	case fingerprint.StageLogin:
		return "Login"
	case fingerprint.StagePrompt:
		return "Prompt"
	case fingerprint.StageBoot:
		return "Bootloader"
	default:
		return string(stage)
	}
}

func boolMarker(enabled bool) string {
	if enabled {
		return "x"
	}
	return " "
}

func runDiagnosticsCmd(iface string, timeout time.Duration, cfg *store.Config) tea.Cmd {
	return func() tea.Msg {
		logging.Infof("Diagnostics command started for %s", iface)
		if cfg == nil {
			cfg = store.DefaultConfig()
		}
		if timeout <= 0 {
			if cfg.DiagnosticsTimeout > 0 {
				timeout = time.Duration(cfg.DiagnosticsTimeout) * time.Millisecond
			} else {
				timeout = 5 * time.Second
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		details, err := netpkg.GetInterfaceDetails(iface)
		if err != nil {
			logging.Errorf("Diagnostics failed to get details: %v", err)
			return diagnoseResultMsg{err: err}
		}

		res, err := diagnostics.Run(ctx, details, cfg)
		if err != nil {
			logging.Errorf("Diagnostics run error: %v", err)
		}
		return diagnoseResultMsg{res: res, err: err}
	}
}

func runSpeedtestCmd() tea.Cmd {
	return func() tea.Msg {
		logging.Infof("Speedtest command started")
		res, err := speedtest.Run()
		if err != nil {
			logging.Errorf("Speedtest error: %v", err)
		}
		return speedtestResultMsg{res: res, err: err}
	}
}

func (m Model) renderStatus() string {
	rootStatus := ""
	if netpkg.IsRoot() {
		rootStatus = " [ROOT]"
	}

	layer := "Iface"
	switch m.layer {
	case LayerMode:
		layer = "Mode"
	case LayerView:
		layer = "View"
	}

	status := fmt.Sprintf("Layer: %s | Interface: %s%s | %s | esc/q: back",
		layer, m.selectedIface, rootStatus, m.statusMsg)

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render(status)
}

// NewModel creates a new TUI model
func NewModel() (*Model, error) {
	// Load config
	config, err := store.LoadConfig()
	if err != nil {
		config = store.DefaultConfig()
	}

	// List user-friendly interfaces (filtered)
	ifaces, err := netpkg.ListUserInterfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}

	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no suitable network interfaces found")
	}

	return &Model{
		mode:          ViewPicker,
		interfaces:    ifaces,
		selectedIndex: 0,
		modeIndex:     0,
		layer:         LayerInterface,
		config:        config,
		statusMsg:     "Select an interface to begin",
	}, nil
}

// Run starts the TUI application
func Run() error {
	model, err := NewModel()
	if err != nil {
		return err
	}

	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// RunWithInterface starts TUI with a pre-selected interface
func RunWithInterface(ifaceName string) error {
	model, err := NewModel()
	if err != nil {
		return err
	}

	// Validate and select interface
	found := false
	for _, iface := range model.interfaces {
		if iface.Name == ifaceName {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("interface %s not found", ifaceName)
	}

	model.selectedIface = ifaceName
	details, err := netpkg.GetInterfaceDetails(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface details: %w", err)
	}

	model.details = details
	model.mode = ViewDetails
	model.layer = LayerView
	model.detailsView = &DetailsView{
		details:     details,
		lastUpdate:  time.Now(),
		autoRefresh: true,
	}

	p := tea.NewProgram(model, tea.WithAltScreen())
	_, err = p.Run()
	return err
}

// RunHeadless prints diagnostics in JSON format
func RunHeadless(ctx context.Context, ifaceName string) error {
	details, err := netpkg.GetInterfaceDetails(ifaceName)
	if err != nil {
		return err
	}

	_, err = store.LoadConfig()
	if err != nil {
		_ = store.DefaultConfig()
	}

	// This would run diagnostics and print JSON
	// For now, just print details
	fmt.Printf("Interface: %s\n", details.Name)
	fmt.Printf("IPs: %v\n", details.IPs)
	fmt.Printf("Gateway: %s\n", details.DefaultGateway)

	return nil
}
