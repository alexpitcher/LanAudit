package console

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alexpitcher/LanAudit/internal/logging"
	"go.bug.st/serial"
)

// SessionConfig defines the configuration for a serial session
type SessionConfig struct {
	PortPath  string
	Baud      int
	DataBits  int
	Parity    string // "N", "O", "E"
	StopBits  int    // 1 or 2
	CRLFMode  string // "CRLF", "CR", "LF"
	LocalEcho bool
	LogToFile bool
}

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig(portPath string, baud int) SessionConfig {
	return SessionConfig{
		PortPath:  portPath,
		Baud:      baud,
		DataBits:  8,
		Parity:    "N",
		StopBits:  1,
		CRLFMode:  "CRLF",
		LocalEcho: false,
		LogToFile: false,
	}
}

// Session represents an active serial console session
type Session struct {
	id           string
	config       SessionConfig
	port         serial.Port
	ctx          context.Context
	cancel       context.CancelFunc
	readChan     chan []byte
	errChan      chan error
	logFile      *os.File
	logFileTxt   *os.File
	mu           sync.RWMutex
	bytesRead    uint64
	bytesWritten uint64
	startTime    time.Time
	dtrState     bool
	rtsState     bool
	watchers     map[chan []byte]struct{}
}

// NewSession creates a new serial console session
func NewSession(ctx context.Context, config SessionConfig) (*Session, error) {
	// Convert parity string to serial.Parity
	var parity serial.Parity
	switch config.Parity {
	case "N":
		parity = serial.NoParity
	case "O":
		parity = serial.OddParity
	case "E":
		parity = serial.EvenParity
	default:
		parity = serial.NoParity
	}

	// Convert stop bits
	var stopBits serial.StopBits
	if config.StopBits == 2 {
		stopBits = serial.TwoStopBits
	} else {
		stopBits = serial.OneStopBit
	}

	// Open port
	mode := &serial.Mode{
		BaudRate: config.Baud,
		DataBits: config.DataBits,
		Parity:   parity,
		StopBits: stopBits,
	}

	port, err := serial.Open(config.PortPath, mode)
	if err != nil {
		logging.Errorf("Session open failed port=%s baud=%d: %v", config.PortPath, config.Baud, err)
		return nil, fmt.Errorf("failed to open port: %w", err)
	}

	// Create session context
	sessionCtx, cancel := context.WithCancel(ctx)

	session := &Session{
		id:        fmt.Sprintf("%s-%d", filepath.Base(config.PortPath), time.Now().Unix()),
		config:    config,
		port:      port,
		ctx:       sessionCtx,
		cancel:    cancel,
		readChan:  make(chan []byte, 100),
		errChan:   make(chan error, 10),
		startTime: time.Now(),
		dtrState:  true, // Usually high by default
		rtsState:  true,
		watchers:  make(map[chan []byte]struct{}),
	}

	// Initialize logging if enabled
	if config.LogToFile {
		if err := session.initLogging(); err != nil {
			port.Close()
			return nil, fmt.Errorf("failed to initialize logging: %w", err)
		}
	}

	// Set initial DTR/RTS
	_ = session.SetDTR(true)
	_ = session.SetRTS(true)

	// Start read goroutine
	go session.readLoop()

	logging.Infof("Session started id=%s port=%s baud=%d", session.id, config.PortPath, config.Baud)

	return session, nil
}

// ID returns the session identifier
func (s *Session) ID() string {
	return s.id
}

// Write sends data to the serial port, applying CR/LF transformation
func (s *Session) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Transform line endings based on CRLFMode
	transformed := s.transformLineEndings(data)

	n, err := s.port.Write(transformed)
	if err != nil {
		logging.Errorf("session %s write error: %v", s.id, err)
		return n, fmt.Errorf("serial write error: %w", err)
	}

	s.bytesWritten += uint64(n)
	logging.Debugf("session %s wrote %d bytes", s.id, n)

	// Log to file if enabled
	if s.logFile != nil {
		s.logFile.Write(transformed)
	}

	return n, nil
}

// SendBreak sends a break signal for the specified duration
func (s *Session) SendBreak(duration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// The go.bug.st/serial library doesn't support SetBreak()
	// Use emulation method instead
	logging.Infof("session %s send break duration=%s", s.id, duration)
	return s.emulateBreak(duration)
}

// emulateBreak emulates a break signal (fallback method)
func (s *Session) emulateBreak(duration time.Duration) error {
	// This is a fallback when SetBreak() is not supported
	// Send null bytes at a lower baud rate to create a break condition
	// Note: This is not as clean as a real break but works in many cases

	// Get current mode
	originalBaud := s.config.Baud

	// Lower baud temporarily
	newMode := &serial.Mode{
		BaudRate: originalBaud / 10,
		DataBits: s.config.DataBits,
	}

	if err := s.port.SetMode(newMode); err != nil {
		return fmt.Errorf("failed to lower baud for break emulation: %w", err)
	}

	// Send null bytes for duration
	nullBytes := int(duration.Milliseconds() / 10)
	if nullBytes < 1 {
		nullBytes = 1
	}

	for i := 0; i < nullBytes; i++ {
		s.port.Write([]byte{0x00})
	}

	// Restore original baud
	originalMode := &serial.Mode{
		BaudRate: originalBaud,
		DataBits: s.config.DataBits,
	}

	return s.port.SetMode(originalMode)
}

// SetDTR sets the DTR (Data Terminal Ready) line
func (s *Session) SetDTR(active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.port.SetDTR(active); err != nil {
		logging.Errorf("session %s set DTR failed: %v", s.id, err)
		return fmt.Errorf("failed to set DTR: %w", err)
	}

	s.dtrState = active
	logging.Debugf("session %s DTR=%v", s.id, active)
	return nil
}

// SetRTS sets the RTS (Request To Send) line
func (s *Session) SetRTS(active bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.port.SetRTS(active); err != nil {
		logging.Errorf("session %s set RTS failed: %v", s.id, err)
		return fmt.Errorf("failed to set RTS: %w", err)
	}

	s.rtsState = active
	logging.Debugf("session %s RTS=%v", s.id, active)
	return nil
}

// GetDTR returns the current DTR state
func (s *Session) GetDTR() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dtrState
}

// GetRTS returns the current RTS state
func (s *Session) GetRTS() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rtsState
}

// ReadChan returns the channel for reading data from the port
func (s *Session) ReadChan() <-chan []byte {
	return s.readChan
}

// ErrorChan returns the channel for errors
func (s *Session) ErrorChan() <-chan error {
	return s.errChan
}

func (s *Session) registerWatcher(ch chan []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchers[ch] = struct{}{}
}

func (s *Session) unregisterWatcher(ch chan []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.watchers, ch)
}

func (s *Session) broadcast(data []byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.watchers {
		copyData := make([]byte, len(data))
		copy(copyData, data)
		select {
		case ch <- copyData:
		default:
		}
	}
}

// ReadUntil reads data mirrored from the serial port until a terminator or timeout.
func (s *Session) ReadUntil(timeout time.Duration, terminators ...[]byte) (string, error) {
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}
	logging.Debugf("session %s ReadUntil timeout=%s terms=%d", s.id, timeout, len(terminators))

	watcher := make(chan []byte, 32)
	s.registerWatcher(watcher)
	defer s.unregisterWatcher(watcher)

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	var builder strings.Builder

	for {
		select {
		case <-s.ctx.Done():
			logging.Warnf("session %s ReadUntil aborted: context done", s.id)
			return builder.String(), fmt.Errorf("session closed")
		case <-timer.C:
			logging.Warnf("session %s ReadUntil timeout", s.id)
			return builder.String(), fmt.Errorf("probe read timeout")
		case chunk := <-watcher:
			if len(chunk) == 0 {
				continue
			}
			builder.Write(chunk)
			logging.Debugf("session %s ReadUntil received chunk len=%d", s.id, len(chunk))

			if len(terminators) == 0 {
				continue
			}

			if matchesTerminator(builder.String(), terminators) {
				logging.Debugf("session %s ReadUntil terminator matched", s.id)
				return builder.String(), nil
			}
		}
	}
}

func matchesTerminator(out string, terms [][]byte) bool {
	trimmed := strings.TrimSpace(out)
	for _, term := range terms {
		if len(term) == 0 {
			continue
		}
		t := strings.TrimSpace(string(term))
		if strings.HasSuffix(trimmed, t) {
			return true
		}
	}
	return false
}

// GetStats returns session statistics
func (s *Session) GetStats() (bytesRead, bytesWritten uint64, duration time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bytesRead, s.bytesWritten, time.Since(s.startTime)
}

// Close closes the serial port and stops the session
func (s *Session) Close() error {
	s.cancel()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Close log files
	if s.logFile != nil {
		s.logFile.Close()
	}
	if s.logFileTxt != nil {
		s.logFileTxt.Close()
	}
	logging.Infof("session %s closed", s.id)

	return s.port.Close()
}

// readLoop continuously reads from the serial port
func (s *Session) readLoop() {
	buffer := make([]byte, 4096)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, err := s.port.Read(buffer)
		if err != nil {
			if err != io.EOF {
				select {
				case s.errChan <- fmt.Errorf("read error: %w", err):
				default:
				}
			}
			continue
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buffer[:n])

			s.mu.Lock()
			s.bytesRead += uint64(n)
			logging.Debugf("session %s read %d bytes", s.id, n)

			// Log to file
			if s.logFile != nil {
				s.logFile.Write(data)
			}
			if s.logFileTxt != nil {
				// Write cleaned version
				cleaned := cleanSerialData(data)
				s.logFileTxt.WriteString(cleaned)
			}
			s.mu.Unlock()

			// Send to channel (non-blocking)
			select {
			case s.readChan <- data:
			default:
				// Channel full, drop data
			}

			s.broadcast(data)
		}
	}
}

// transformLineEndings applies CR/LF transformation based on config
func (s *Session) transformLineEndings(data []byte) []byte {
	if s.config.CRLFMode == "CRLF" {
		// Replace \n with \r\n
		result := make([]byte, 0, len(data)*2)
		for _, b := range data {
			if b == '\n' {
				result = append(result, '\r', '\n')
			} else {
				result = append(result, b)
			}
		}
		return result
	} else if s.config.CRLFMode == "CR" {
		// Replace \n with \r
		result := make([]byte, len(data))
		for i, b := range data {
			if b == '\n' {
				result[i] = '\r'
			} else {
				result[i] = b
			}
		}
		return result
	}

	// LF mode - no transformation
	return data
}

// initLogging sets up log files
func (s *Session) initLogging() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	logDir := filepath.Join(home, ".lanaudit", "console")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")
	baseName := filepath.Base(s.config.PortPath)

	// Raw log
	rawPath := filepath.Join(logDir, fmt.Sprintf("%s-%s.log", timestamp, baseName))
	s.logFile, err = os.Create(rawPath)
	if err != nil {
		return err
	}

	// Text log
	txtPath := filepath.Join(logDir, fmt.Sprintf("%s-%s.txt", timestamp, baseName))
	s.logFileTxt, err = os.Create(txtPath)
	if err != nil {
		s.logFile.Close()
		return err
	}

	return nil
}

// GetLogPath returns the path to the log file if logging is enabled
func (s *Session) GetLogPath() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.logFile != nil {
		return s.logFile.Name()
	}
	return ""
}
