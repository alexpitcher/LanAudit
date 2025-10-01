package console

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alexpitcher/LanAudit/internal/console/fingerprint"
	"github.com/alexpitcher/LanAudit/internal/logging"
	"go.bug.st/serial"
)

// ProbeConfig defines parameters for baud probing
type ProbeConfig struct {
	BaudRates []int
	Timeout   time.Duration
	MaxBytes  int
}

// DefaultProbeConfig returns sensible defaults for probing
func DefaultProbeConfig() ProbeConfig {
	return ProbeConfig{
		BaudRates: []int{9600, 115200},
		Timeout:   800 * time.Millisecond,
		MaxBytes:  2048,
	}
}

// ProbeResult contains the results of a baud probe
type ProbeResult struct {
	Success     bool
	Baud        int
	RawData     []byte
	CleanedData string
	Fingerprint fingerprint.Result
	Candidates  []fingerprint.Candidate
	Stage       fingerprint.Stage
	Error       error
}

// ProbePort attempts to detect the correct baud rate and fingerprint the device
func ProbePort(ctx context.Context, portPath string, config ProbeConfig) ProbeResult {
	result := ProbeResult{
		Success: false,
	}

	logging.Infof("ProbePort start path=%s bauds=%v timeout=%s", portPath, config.BaudRates, config.Timeout)

	// Try each baud rate in order
	for _, baud := range config.BaudRates {
		logging.Debugf("probing %s at %d baud", portPath, baud)
		pr := probeSingleBaud(ctx, portPath, baud, config)
		if pr.Success {
			result = pr
			promptLine := fingerprint.ExtractLastPromptLine(result.CleanedData)
			stage, cands := fingerprint.Analyze(result.CleanedData, promptLine)
			result.Stage = stage
			result.Candidates = cands
			result.Fingerprint = fingerprint.Finalize(stage, cands, result.CleanedData, promptLine, "")
			result.Fingerprint.Baud = baud
			logging.Infof("probe success baud=%d stage=%s vendor=%s os=%s", baud, stage, result.Fingerprint.Vendor, result.Fingerprint.OS)
			return result
		}

		// If we got some data but it looks like garbage, note it
		if len(pr.RawData) > 0 {
			result.RawData = pr.RawData
			result.CleanedData = pr.CleanedData
		}
	}

	// All baud rates failed
	result.Error = fmt.Errorf("no response at any baud rate (%v)", config.BaudRates)
	logging.Warnf("probe failed for %s: %v", portPath, result.Error)
	result.Fingerprint = fingerprint.Result{
		Vendor:     "Unknown",
		OS:         "Unknown",
		Stage:      fingerprint.StagePreLogin,
		Confidence: 0,
		Evidence:   []string{"No response at configured baud rates"},
	}

	return result
}

// probeSingleBaud tries a single baud rate
func probeSingleBaud(ctx context.Context, portPath string, baud int, config ProbeConfig) ProbeResult {
	result := ProbeResult{
		Baud: baud,
	}

	// Open port
	mode := &serial.Mode{
		BaudRate: baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}

	port, err := serial.Open(portPath, mode)
	if err != nil {
		result.Error = fmt.Errorf("failed to open port: %w", err)
		logging.Errorf("serial open failed %s baud=%d: %v", portPath, baud, err)
		return result
	}
	defer port.Close()

	// Set read timeout
	if err := port.SetReadTimeout(config.Timeout); err != nil {
		result.Error = fmt.Errorf("failed to set timeout: %w", err)
		logging.Errorf("set timeout failed %s: %v", portPath, err)
		return result
	}

	// Send gentle wake-up prompts
	prompts := [][]byte{
		[]byte("\r\n"),         // Wake
		[]byte("\r\r\r\r\r"),   // Spam ENTER to coax banners
		[]byte("\r\n?\r\n"),    // Help prompt
		[]byte("\r\n\x03\r\n"), // Ctrl-C
	}

	for i, prompt := range prompts {
		if ctx.Err() != nil {
			result.Error = ctx.Err()
			logging.Warnf("probe aborted %s baud=%d: %v", portPath, baud, result.Error)
			return result
		}

		_, _ = port.Write(prompt)
		logging.Debugf("sent wake sequence %d (% X) to %s", i, prompt, portPath)

		// Wait a bit between prompts
		if i < len(prompts)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	// Read response
	buffer := make([]byte, config.MaxBytes)
	totalRead := 0

	// Read in chunks with timeout
	readDeadline := time.Now().Add(config.Timeout)
	for time.Now().Before(readDeadline) && totalRead < config.MaxBytes {
		if ctx.Err() != nil {
			result.Error = ctx.Err()
			return result
		}

		n, err := port.Read(buffer[totalRead:])
		if n > 0 {
			totalRead += n
		}

		if err != nil {
			// Timeout is expected
			logging.Debugf("read timeout or error after %d bytes: %v", totalRead, err)
			break
		}

		// If we got some data, give it a bit more time to complete
		if n > 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Store raw data
	result.RawData = buffer[:totalRead]

	// Clean data for analysis
	result.CleanedData = cleanSerialData(result.RawData)

	// Determine success - we got meaningful data if:
	// 1. We have at least 10 bytes
	// 2. The cleaned data has some printable content
	if totalRead >= 10 && len(strings.TrimSpace(result.CleanedData)) > 5 {
		result.Success = true
		logging.Debugf("probeSingleBaud success %s baud=%d read=%d bytes", portPath, baud, totalRead)
	}

	return result
}

// cleanSerialData converts raw bytes to UTF-8 string, replacing non-printables
func cleanSerialData(data []byte) string {
	// First, try to convert to valid UTF-8
	if !utf8.Valid(data) {
		// Replace invalid sequences
		data = []byte(strings.ToValidUTF8(string(data), "�"))
	}

	// Build cleaned string
	var b strings.Builder
	for _, r := range string(data) {
		switch {
		case r == '\r' || r == '\n' || r == '\t':
			// Keep these control characters
			b.WriteRune(r)
		case r >= 32 && r <= 126:
			// Printable ASCII
			b.WriteRune(r)
		case r >= 128 && r < 0xFFFD:
			// Extended characters (might be valid UTF-8)
			b.WriteRune(r)
		case r == 0x1B:
			// Escape character (for ANSI sequences) - keep it
			b.WriteRune(r)
		default:
			// Replace other control characters with space
			b.WriteRune(' ')
		}
	}

	return b.String()
}

// QuickProbe performs a fast probe with default settings
func QuickProbe(portPath string) ProbeResult {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	config := DefaultProbeConfig()
	return ProbePort(ctx, portPath, config)
}
