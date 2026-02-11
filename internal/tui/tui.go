package tui

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/alexpitcher/LanAudit/internal/capture"
	"github.com/alexpitcher/LanAudit/internal/console"
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
	ViewLLDP
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

	// Help overlay
	helpActive bool

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

type extendedDetailsMsg struct {
	speed     string
	ifaceType string
	err       error
}

type auditResultMsg struct {
	result *scan.ScanResult
	err    error
}

type startCaptureMsg struct {
	err error
}

type stopCaptureMsg struct {
	err error
}

type saveCaptureMsg struct {
	filename string
	err      error
}

type lldpResultMsg struct {
	neighbors []netpkg.LLDPNeighbor
	err       error
}

type snapshotResultMsg struct {
	path string
	err  error
}

type consolePortsMsg struct {
	ports []console.SerialPort
	err   error
}

type consoleSessionMsg struct {
	session *console.Session
	err     error
}

type consoleProbeMsg struct {
	result console.ProbeResult
}

type consoleDataMsg struct {
	data []byte
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

	case auditResultMsg:
		if m.auditView != nil {
			m.auditView.running = false
			m.auditView.result = msg.result
			m.auditView.err = msg.err
			if msg.err != nil {
				m.auditView.statusMessage = fmt.Sprintf("Audit failed: %v", msg.err)
			} else {
				m.auditView.statusMessage = fmt.Sprintf("Audit complete. Found %d active hosts.", msg.result.ActiveHosts)
			}
		}
		return m, nil

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

	case extendedDetailsMsg:
		if m.detailsView != nil {
			if msg.err != nil {
				logging.Warnf("failed to load extended details: %v", msg.err)
				m.details.Speed = "Error"
				m.details.Type = "Error"
			} else {
				m.details.Speed = msg.speed
				m.details.Type = msg.ifaceType
			}
			m.detailsView.lastUpdate = time.Now()
		}
		return m, nil

	case startCaptureMsg:
		if m.captureView != nil {
			if msg.err != nil {
				m.captureView.running = false
				m.captureView.statusMessage = fmt.Sprintf("Capture failed: %v", msg.err)
				// Also set global error and status message
				m.err = msg.err
				m.statusMsg = m.captureView.statusMessage
				logging.Warnf("capture failed to start: %v", msg.err)
			} else {
				m.captureView.running = true
				m.captureView.statusMessage = "Capturing packets..."
				m.captureSession = capture.GetCurrentSession()
				logging.Infof("capture started successfully")
			}
		}
		return m, nil

	case stopCaptureMsg:
		if m.captureView != nil {
			m.captureView.running = false
			if msg.err != nil {
				m.captureView.statusMessage = fmt.Sprintf("Stop failed: %v", msg.err)
				logging.Warnf("capture failed to stop: %v", msg.err)
			} else {
				m.captureView.statusMessage = "Capture stopped"
				logging.Infof("capture stopped successfully")
			}
		}
		return m, nil

	case saveCaptureMsg:
		if m.captureView != nil {
			if msg.err != nil {
				m.captureView.statusMessage = fmt.Sprintf("Save failed: %v", msg.err)
				logging.Warnf("failed to save capture: %v", msg.err)
			} else {
				m.captureView.statusMessage = fmt.Sprintf("Saved to %s", msg.filename)
				logging.Infof("capture saved to %s", msg.filename)
			}
		}
		return m, nil

	case speedtestResultMsg:
		if m.speedtestView == nil {
			m.speedtestView = &SpeedtestView{}
		}
		// If user cancelled, ignore result
		if !m.speedtestView.running && m.speedtestView.statusMessage == "Speedtest cancelled" {
			return m, nil
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
				// Preserve slow-loading fields from existing details
				if m.details != nil && m.details.Name == details.Name {
					details.Speed = m.details.Speed
					details.Type = m.details.Type
				}

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
		// Sync capture state
		if m.captureView != nil && m.captureView.running {
			sess := capture.GetCurrentSession()
			if sess == nil || !sess.IsRunning() {
				m.captureView.running = false
				m.captureView.statusMessage = "Capture stopped (limit reached or external stop)"
				logging.Infof("capture state synced: stopped")
			}
		}
		return m, tick()

	case consolePortsMsg:
		if m.consoleView != nil {
			if msg.err != nil {
				m.consoleView.statusMessage = fmt.Sprintf("Error finding ports: %v", msg.err)
			} else {
				m.consoleView.ports = make([]interface{}, len(msg.ports))
				for i, p := range msg.ports {
					m.consoleView.ports[i] = p
				}
				if len(m.consoleView.ports) > 0 {
					m.consoleView.selectedPort = 0
					m.consoleView.statusMessage = fmt.Sprintf("Found %d ports. Select and press Enter.", len(m.consoleView.ports))
				} else {
					m.consoleView.statusMessage = "No serial ports found."
				}
			}
		}
		return m, nil

	case consoleSessionMsg:
		if m.consoleView != nil {
			if msg.err != nil {
				m.consoleView.statusMessage = fmt.Sprintf("Connection failed: %v", msg.err)
			} else {
				m.consoleView.session = msg.session
				m.consoleView.statusMessage = fmt.Sprintf("Connected to %s", msg.session.ID())
				// Start reading data
				return m, readConsoleDataCmd(msg.session)
			}
		}
		return m, nil

	case consoleDataMsg:
		if m.consoleView != nil && m.consoleView.session != nil {
			// Append valid UTF-8 string to buffer
			text := string(msg.data) // Simplified; real impl should sanitise
			lines := strings.Split(text, "\n")
			for _, line := range lines {
				if line != "" {
					m.consoleView.buffer = append(m.consoleView.buffer, line)
				}
			}
			// Keep buffer size reasonable
			if len(m.consoleView.buffer) > 1000 {
				m.consoleView.buffer = m.consoleView.buffer[len(m.consoleView.buffer)-1000:]
			}
			// Continue reading
			return m, readConsoleDataCmd(m.consoleView.session.(*console.Session))
		}
		return m, nil

	case consoleProbeMsg:
		if m.consoleView != nil {
			m.consoleView.probeStatus = "Done"
			if msg.result.Success {
				fp := msg.result.Fingerprint
				m.consoleView.fingerprint = &fp
				m.consoleView.statusMessage = fmt.Sprintf("Probe success: %s", fp.Vendor)
			} else {
				m.consoleView.statusMessage = fmt.Sprintf("Probe failed: %v", msg.result.Error)
			}
		}
		return m, nil

	case lldpResultMsg:
		if m.lldpView == nil {
			m.lldpView = &LLDPView{}
		}
		m.lldpView.running = false
		m.lldpView.err = msg.err
		if msg.err != nil {
			m.lldpView.statusMessage = fmt.Sprintf("LLDP discovery failed: %v", msg.err)
			logging.Warnf(m.lldpView.statusMessage)
		} else {
			m.lldpView.neighbors = msg.neighbors
			m.lldpView.statusMessage = fmt.Sprintf("Discovery complete. Found %d neighbors.", len(msg.neighbors))
			logging.Infof("LLDP discovery complete, found %d neighbors", len(msg.neighbors))
		}
		return m, nil

	case error:
		logging.Errorf("tui received error: %v", msg)
		m.err = msg
		return m, nil
	}

	return m, nil
}

// handleKeys processes keyboard input
func (m Model) handleKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Global input handling
	if m.inputActive {
		switch msg.Type {
		case tea.KeyEnter:
			m.inputActive = false
			if m.inputSubmit != nil {
				return m, m.inputSubmit(&m, m.inputValue)
			}
			return m, nil
		case tea.KeyEsc:
			m.inputActive = false
			m.inputValue = ""
			m.inputPrompt = ""
			m.statusMsg = "Input cancelled"
			return m, nil
		case tea.KeyBackspace, tea.KeyDelete:
			if len(m.inputValue) > 0 {
				m.inputValue = m.inputValue[:len(m.inputValue)-1]
			}
		case tea.KeyRunes:
			m.inputValue += msg.String()
		case tea.KeySpace:
			m.inputValue += " "
		}
		return m, nil
	}

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
		if m.mode == ViewSettings && m.layer == LayerView && m.config != nil {
			m.config.Redact = !m.config.Redact
			m.statusMsg = fmt.Sprintf("Redact mode: %v", m.config.Redact)
			if err := store.SaveConfig(m.config); err != nil {
				logging.Errorf("failed to save config: %v", err)
			}
			return m, nil
		}

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

	case "t":
		if m.mode == ViewSettings && m.layer == LayerView && m.config != nil {
			timeouts := []int{1000, 2000, 5000, 10000}
			current := m.config.DiagnosticsTimeout
			next := timeouts[0]
			for i, t := range timeouts {
				if current == t && i < len(timeouts)-1 {
					next = timeouts[i+1]
					break
				}
			}
			m.config.DiagnosticsTimeout = next
			m.statusMsg = fmt.Sprintf("Diagnostics timeout set to %dms", next)
			if err := store.SaveConfig(m.config); err != nil {
				logging.Errorf("failed to save config: %v", err)
			}
			return m, nil
		}

	case "s":
		if m.mode == ViewCapture && m.layer == LayerView {
			if m.captureView == nil {
				m.captureView = &CaptureView{}
			}
			// Check if backend is actually running, not just UI state
			isRunning := false
			if m.captureView.running {
				if sess := capture.GetCurrentSession(); sess != nil && sess.IsRunning() {
					isRunning = true
				} else {
					// UI thinks running but backend dead -> reset
					m.captureView.running = false
					logging.Warnf("capture UI state desync detected, resetting to stopped")
				}
			}

			if isRunning {
				logging.Debugf("capture already running")
				break
			}
			m.captureView.running = true
			m.captureView.statusMessage = "Starting capture..."
			m.statusMsg = m.captureView.statusMessage
			logging.Infof("starting capture on %s", m.selectedIface)
			return m, startCaptureCmd(m.selectedIface, m.captureView.filter)
		}
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
		if m.mode == ViewAudit && m.layer == LayerView {
			if m.auditView == nil {
				m.auditView = &AuditView{}
			}
			if m.auditView.running {
				break
			}
			m.auditView.running = true
			m.auditView.statusMessage = "Scanning network..."
			m.statusMsg = "Running Audit..."
			gateway := ""
			if m.details != nil {
				gateway = m.details.DefaultGateway
			}
			return m, runAuditCmd(gateway)
		}
		if m.mode == ViewLLDP && m.layer == LayerView {
			if m.lldpView == nil {
				m.lldpView = &LLDPView{}
			}
			if m.lldpView.running {
				break
			}
			m.lldpView.running = true
			m.lldpView.statusMessage = "Listening for LLDP packets..."
			m.statusMsg = "Running LLDP Discovery..."
			return m, runLLDPCmd(m.selectedIface, 30*time.Second)
		}
		if m.layer == LayerView {
			break
		}
		m = m.activateMode(ViewSettings)
		m.layer = LayerView
		m.statusMsg = "Settings"
		logging.Infof("key 's' -> ViewSettings")

	case "f":
		if m.mode == ViewCapture && m.layer == LayerView {
			m.inputActive = true
			m.inputPrompt = "BPF Filter (e.g. 'tcp port 80'): "
			m.inputValue = m.captureView.filter
			m.inputSubmit = func(m *Model, val string) tea.Cmd {
				m.captureView.filter = val
				m.statusMsg = fmt.Sprintf("Filter set to: %s", val)
				return nil
			}
			m.statusMsg = "Enter BPF filter..."
			return m, nil
		}
		if m.mode == ViewConsole && m.layer == LayerView {
			if m.consoleView != nil {
				m.consoleView.statusMessage = "Refreshing ports..."
				return m, discoverPortsCmd()
			}
		}

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

	case "x":
		if m.mode == ViewCapture && m.layer == LayerView {
			// Stop capture
			if m.captureView != nil && m.captureView.running {
				m.captureView.statusMessage = "Stopping capture..."
				m.statusMsg = "Stopping..."
				logging.Infof("stopping capture")
				return m, stopCaptureCmd()
			}
		}
		if m.mode == ViewSpeedtest && m.layer == LayerView {
			// Cancel speedtest
			if m.speedtestView != nil && m.speedtestView.running {
				m.speedtestView.running = false
				m.speedtestView.statusMessage = "Speedtest cancelled"
				m.statusMsg = "Speedtest cancelled"
				logging.Infof("speedtest cancelled by user")
			}
		}
		if m.mode == ViewConsole && m.layer == LayerView && m.consoleView != nil && m.consoleView.session != nil {
			// Close console session
			sess := m.consoleView.session.(*console.Session)
			m.consoleView.session = nil
			m.consoleView.statusMessage = "Session closed"
			return m, closeConsoleSessionCmd(sess)
		}

	case "w":
		if m.mode == ViewCapture && m.layer == LayerView {
			if m.captureView != nil {
				if m.captureSession == nil || m.captureSession.GetPacketCount() == 0 {
					m.captureView.statusMessage = "No packets to save"
					break
				}
				filename := fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))
				m.captureView.statusMessage = fmt.Sprintf("Saving to %s...", filename)
				return m, saveCaptureCmd(filename)
			}
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
		if m.mode == ViewConsole && m.layer == LayerView {
			if m.consoleView != nil && len(m.consoleView.ports) > 0 {
				port := m.consoleView.ports[m.consoleView.selectedPort].(console.SerialPort).Path
				m.consoleView.statusMessage = fmt.Sprintf("Probing %s...", port)
				m.consoleView.probeStatus = "Running..."
				return m, probePortCmd(context.Background(), port)
			}
			break
		}

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
			m = m.activateMode(ViewLLDP)
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
				selectedPort:           0,
				buffer:                 make([]string, 0),
				statusMessage:          "Press 'f' to discover ports",
				dtrState:               true,
				rtsState:               true,
				logging:                false,
				allowProbeInConfigMode: m.config != nil && m.config.Console.AllowProbeInConfigMode,
			}
			return m, discoverPortsCmd()
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
				if err := store.SaveConfig(m.config); err != nil {
					logging.Errorf("failed to save config: %v", err)
				}
			}
			if m.consoleView.allowProbeInConfigMode {
				m.statusMsg = "Config-mode probes enabled"
				logging.Warnf("config-mode probes enabled by user")
			} else {
				m.statusMsg = "Config-mode probes disabled"
				logging.Infof("config-mode probes disabled by user")
			}
		}

	default:
		// Forward typing to console session if active
		if m.mode == ViewConsole && m.consoleView != nil && m.consoleView.session != nil {
			// Filter out navigation keys that shouldn't be forwarded if handled above
			// But since we are directly in case default, these are keys NOT handled above.
			// However, bubbletea keys like "enter", "up", etc are separate from runes.
			// We only want to forward runes or specific control keys.
			if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace {
				sess := m.consoleView.session.(*console.Session)
				return m, sendConsoleDataCmd(sess, []byte(msg.String()))
			} else if msg.Type == tea.KeyEnter {
				// Enter is handled in separate case "enter" below...
				// Wait, "enter" case below is for navigation/selection.
				// If session is active, "enter" should be forwarded!
				// I need to modify the "enter" case to forward if session is active.
			}
		}

	case "up", "k":
		if m.mode == ViewConsole && m.layer == LayerView {
			if m.consoleView != nil && len(m.consoleView.ports) > 0 && m.consoleView.session == nil {
				count := len(m.consoleView.ports)
				m.consoleView.selectedPort = (m.consoleView.selectedPort - 1 + count) % count
			}
			return m, nil
		}
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
		if m.mode == ViewConsole && m.layer == LayerView {
			if m.consoleView != nil && len(m.consoleView.ports) > 0 && m.consoleView.session == nil {
				count := len(m.consoleView.ports)
				m.consoleView.selectedPort = (m.consoleView.selectedPort + 1) % count
			}
			return m, nil
		}
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
		} else if m.layer == LayerMode {
			idx := int(msg.Runes[0]-'0') - 1
			modes := m.availableModes()
			if idx >= 0 && idx < len(modes) {
				sel := modes[idx]
				m = m.activateMode(sel.mode)
				m.layer = LayerView
				logging.Infof("digit %s -> activate mode %v", msg.String(), sel.mode)

				// Trigger extended details if entering Details view
				if sel.mode == ViewDetails && m.selectedIface != "" {
					return m, getExtendedDetailsCmd(m.selectedIface)
				}
			}
		}

	case "enter":
		if m.mode == ViewConsole && m.layer == LayerView {
			// If session is active, forward Enter
			if m.consoleView != nil && m.consoleView.session != nil {
				sess := m.consoleView.session.(*console.Session)
				// Send CR (or CRLF depending on config, but usually CR)
				return m, sendConsoleDataCmd(sess, []byte("\r"))
			}

			// Connect to selected port
			if m.consoleView != nil && len(m.consoleView.ports) > 0 && m.consoleView.session == nil {
				port := m.consoleView.ports[m.consoleView.selectedPort].(console.SerialPort)
				m.consoleView.statusMessage = fmt.Sprintf("Connecting to %s...", port.Path)
				return m, openConsoleSessionCmd(context.Background(), port.Path, 115200) // Default baud
			}
			return m, nil
		}

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

			// Trigger extended details if entering Details view
			if sel.mode == ViewDetails && m.selectedIface != "" {
				return m, getExtendedDetailsCmd(m.selectedIface)
			}
		}
	}

	// Also check for mode switches from other keys
	if m.mode == ViewDetails && m.layer == LayerView && m.detailsView != nil && m.detailsView.details.Speed == "" {
		// This handles the 'd' key shortcut case
		return m, getExtendedDetailsCmd(m.selectedIface)
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
		content := lipgloss.JoinVertical(lipgloss.Left,
			m.renderContent(),
			m.renderStatus(),
		)
		if m.inputActive {
			// Overlay input box
			inputStyle := lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				Padding(1, 2).
				BorderForeground(lipgloss.Color("63"))

			inputBox := inputStyle.Render(fmt.Sprintf("%s\n%s_", m.inputPrompt, m.inputValue))

			// Center the input box (rough approximation)
			return lipgloss.Place(m.width, m.height,
				lipgloss.Center, lipgloss.Center,
				inputBox,
				lipgloss.WithWhitespaceChars(" "),
				// lipgloss.WithWhitespaceForeground(lipgloss.NoColor), // Removed to fix type error
			)
		} else if m.helpActive {
			// Overlay Help
			helpBox := m.renderHelp()
			return lipgloss.Place(m.width, m.height,
				lipgloss.Center, lipgloss.Center,
				helpBox,
				lipgloss.WithWhitespaceChars(" "),
			)
		}
		return content
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
		statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10")) // Green
		if iface.Flags&net.FlagUp == 0 {
			status = "DOWN"
			statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")) // Red
		}
		statusStr := statusStyle.Render(status)

		// Line 1: Number, name, status, IP (fixed width alignment)
		// Total width inside ║ ║ is 66 chars
		// Note: We construct string first to calculate padding, then inject colored status
		line1Raw := fmt.Sprintf("%d. %-8s [%s]  %s", i+1, iface.Name, status, ipAddr)
		padding := 63 - len(line1Raw)
		if padding < 0 {
			padding = 0
		}

		line1 := fmt.Sprintf("%d. %-8s [%s]  %s%s", i+1, iface.Name, statusStr, ipAddr, strings.Repeat(" ", padding))
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
	s += "║ Arrow keys: Navigate  |  1-9: Quick select  |  ENTER: Select     ║\n"
	s += "║ q/esc: Back/quit                                                 ║\n"
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
		{"[v] VLAN [WIP]", ViewVLAN},
		{"[n] Snap [WIP]", ViewSnap},
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
	case ViewLLDP:
		return m.renderLLDPView()
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

	s += "═══ Interface Details ═══\n\n"
	s += fmt.Sprintf("Interface:  %s\n", m.details.Name)
	s += fmt.Sprintf("MAC:        %s\n", m.details.MAC)
	s += fmt.Sprintf("MTU:        %d bytes\n", m.details.MTU)
	s += fmt.Sprintf("Link:       %s\n", linkStatus)
	speed := m.details.Speed
	if speed == "" {
		speed = "Loading..."
	}
	s += fmt.Sprintf("Speed:      %s\n", speed)
	if m.details.Type != "" {
		s += fmt.Sprintf("Type:       %s\n", m.details.Type)
	}
	s += "\n"

	s += "═══ IP Addresses ═══\n"
	if len(m.details.IPs) > 0 {
		for _, ip := range m.details.IPs {
			s += fmt.Sprintf("  %s\n", ip)
		}
	} else {
		s += "  No IP addresses configured\n"
	}

	s += "\n═══ Network ═══\n"
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

	s += "\n═══ Traffic Statistics ═══\n"
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

	s.WriteString("\nPress 'r' to re-run diagnostics.\n")

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
	s += fmt.Sprintf("Diagnostics Timeout: %dms (press 't' to cycle)\n", m.config.DiagnosticsTimeout)
	s += fmt.Sprintf("Redact Mode: %v (press 'r' to toggle)\n", m.config.Redact)
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
		count := 0
		if m.captureSession != nil {
			count = m.captureSession.GetPacketCount()
		}
		s += fmt.Sprintf("Packets captured: %d\n\n", count)
		s += "Press 'x' to stop capture\n\n"
	} else {
		s += "Commands:\n"
		s += "  's' - Start capture (requires sudo/root)\n"
		if m.captureSession != nil && m.captureSession.GetPacketCount() > 0 {
			s += "  'w' - Save capture to PCAP file\n"
		}
		s += "  'f' - Set BPF filter\n"
		s += "\nNote: Packet capture requires root privileges.\n\n"
	}

	// Show packet list
	s += "Last Packets:\n"
	s += "──────────────────────────────────────────────────────────────\n"
	if m.captureSession != nil {
		packets := m.captureSession.GetPackets()
		start := len(packets) - 15
		if start < 0 {
			start = 0
		}
		for i := start; i < len(packets); i++ {
			p := packets[i]
			ts := p.Timestamp.Format("15:04:05.000")
			info := p.Info
			if len(info) > 30 {
				info = info[:27] + "..."
			}
			s += fmt.Sprintf("[%s] %s -> %s (%s) %s\n",
				ts, p.SourceIP, p.DestIP, p.Protocol, info)
		}
	}
	s += "──────────────────────────────────────────────────────────────\n"

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
			s += "\n"
			for i, p := range m.consoleView.ports {
				port, ok := p.(console.SerialPort)
				if !ok {
					continue
				}
				marker := " "
				if i == m.consoleView.selectedPort {
					marker = ">"
				}
				s += fmt.Sprintf(" %s %s (%s)\n", marker, port.Path, port.FriendlyName)
			}
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

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			p.ReleaseTerminal()
			fmt.Printf("LanAudit crashed: %v\n", r)
			logging.Errorf("PANIC: %v", r)
			os.Exit(1)
		}
	}()

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

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			p.ReleaseTerminal()
			fmt.Printf("LanAudit crashed: %v\n", r)
			logging.Errorf("PANIC: %v", r)
			os.Exit(1)
		}
	}()

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

func getExtendedDetailsCmd(iface string) tea.Cmd {
	return func() tea.Msg {
		speed, ifaceType, err := netpkg.GetExtendedInterfaceDetails(iface)
		return extendedDetailsMsg{speed: speed, ifaceType: ifaceType, err: err}
	}
}

func startCaptureCmd(iface, filter string) tea.Cmd {
	return func() tea.Msg {
		if !netpkg.HasPcapPermissions() {
			return startCaptureMsg{err: fmt.Errorf("root/sudo permissions required for packet capture")}
		}
		_, err := capture.Start(iface, filter, 1000) // Limit to 1000 packets for TUI safety
		return startCaptureMsg{err: err}
	}
}

func stopCaptureCmd() tea.Cmd {
	return func() tea.Msg {
		err := capture.StopCurrentSession()
		return stopCaptureMsg{err: err}
	}
}

func saveCaptureCmd(filename string) tea.Cmd {
	return func() tea.Msg {
		session := capture.GetCurrentSession()
		if session == nil {
			return saveCaptureMsg{filename: filename, err: fmt.Errorf("no active session")}
		}
		err := session.SaveToPCAP(filename)
		return saveCaptureMsg{filename: filename, err: err}
	}
}

func runAuditCmd(gateway string) tea.Cmd {
	return func() tea.Msg {
		if gateway == "" {
			return auditResultMsg{err: fmt.Errorf("no gateway configured")}
		}
		// Use real audit with fast timeout (500ms per host)
		res, err := scan.AuditGateway(gateway, nil, 500*time.Millisecond)
		return auditResultMsg{result: res, err: err}
	}
}

func runLLDPCmd(iface string, duration time.Duration) tea.Cmd {
	return func() tea.Msg {
		neighbors, err := netpkg.DiscoverLLDP(iface, duration)
		return lldpResultMsg{neighbors: neighbors, err: err}
	}
}

func discoverPortsCmd() tea.Cmd {
	return func() tea.Msg {
		ports, err := console.DiscoverPorts()
		return consolePortsMsg{ports: ports, err: err}
	}
}

func openConsoleSessionCmd(ctx context.Context, port string, baud int) tea.Cmd {
	return func() tea.Msg {
		cfg := console.DefaultSessionConfig(port, baud)
		sess, err := console.NewSession(ctx, cfg)
		return consoleSessionMsg{session: sess, err: err}
	}
}

func closeConsoleSessionCmd(sess *console.Session) tea.Cmd {
	return func() tea.Msg {
		sess.Close()
		return nil
	}
}

func probePortCmd(ctx context.Context, port string) tea.Cmd {
	return func() tea.Msg {
		res := console.QuickProbe(port)
		return consoleProbeMsg{result: res}
	}
}

func readConsoleDataCmd(sess *console.Session) tea.Cmd {
	return func() tea.Msg {
		select {
		case data := <-sess.ReadChan():
			return consoleDataMsg{data: data}
		case err := <-sess.ErrorChan():
			return err
		case <-time.After(100 * time.Millisecond):
			return nil
		}
	}
}

func sendConsoleDataCmd(sess *console.Session, data []byte) tea.Cmd {
	return func() tea.Msg {
		_, err := sess.Write(data)
		if err != nil {
			logging.Errorf("failed to write to console: %v", err)
		}
		return nil
	}
}

func (m Model) renderHelp() string {
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		BorderForeground(lipgloss.Color("63"))

	var s string
	s += lipgloss.NewStyle().Bold(true).Render("Help") + "\n\n"
	s += "General Navigation:\n"
	s += "  Arrow Keys / hjkl : Navigate\n"
	s += "  Enter             : Select / Activate\n"
	s += "  Esc / q           : Back / Quit\n"
	s += "  ?                 : Toggle Help\n\n"

	s += "Context Commands:\n"
	switch m.mode {
	case ViewPicker, ViewDetails:
		s += "  1-9 : Quick Select Interface\n"
		s += "  d   : Refresh Details\n"
	case ViewDiagnose:
		s += "  r   : Run Diagnostics\n"
	case ViewSettings:
		s += "  r   : Toggle Redact Mode\n"
		s += "  t   : Cycle Timeout\n"
	case ViewCapture:
		s += "  s   : Start Capture\n"
		s += "  x   : Stop Capture\n"
		s += "  w   : Save to PCAP\n"
		s += "  f   : Set Filter\n"
	case ViewAudit:
		s += "  s   : Start Audit\n"
	case ViewSpeedtest:
		s += "  s   : Start Speedtest\n"
		s += "  x   : Cancel Speedtest\n"
	case ViewConsole:
		s += "  f   : Refresh Ports\n"
		s += "  p   : Probe Port\n"
		s += "  Enter: Connect\n"
		s += "  x   : Disconnect\n"
		s += "  P   : Safe Probe (Active)\n"
		s += "  A   : Toggle Config Probe\n"
		s += "  Type to send to console\n"
	}

	return style.Render(s)
}

func (m Model) renderLLDPView() string {
	if m.lldpView == nil {
		return "LLDP view not initialized"
	}

	var s string
	s += "═══ LLDP Neighbors ═══\n\n"
	s += fmt.Sprintf("Status: %s\n\n", m.lldpView.statusMessage)

	if m.lldpView.running {
		s += "Listening for LLDP packets (30s timeout)...\n"
		return s
	}

	if len(m.lldpView.neighbors) == 0 {
		s += "No neighbors found.\n\n"
		s += "Commands:\n"
		s += "  's' - Start Discovery (requires sudo/root)\n"
		return s
	}

	// Simple table
	s += fmt.Sprintf("%-20s %-20s %-15s %-20s\n", "System Name", "Chassis ID", "Port ID", "Mgmt IP")
	s += strings.Repeat("─", 80) + "\n"

	for _, n := range m.lldpView.neighbors {
		sysName := n.SystemName
		if len(sysName) > 19 {
			sysName = sysName[:19]
		}
		chassis := n.ChassisID
		if len(chassis) > 19 {
			chassis = chassis[:19]
		}
		port := n.PortID
		if len(port) > 14 {
			port = port[:14]
		}
		
		s += fmt.Sprintf("%-20s %-20s %-15s %-20s\n", sysName, chassis, port, n.ManagementAddr)
		
		// Detailed info
		s += fmt.Sprintf("  %s\n", n.SystemDesc)
		if len(n.Capabilities) > 0 {
			s += fmt.Sprintf("  Caps: %v\n", n.Capabilities)
		}
		s += "\n"
	}

	return s
}
