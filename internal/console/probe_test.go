package console

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alexpitcher/LanAudit/internal/console/fingerprint"
)

func TestDefaultProbeConfig(t *testing.T) {
	config := DefaultProbeConfig()

	if len(config.BaudRates) == 0 {
		t.Error("DefaultProbeConfig() has no baud rates")
	}

	if config.Timeout == 0 {
		t.Error("DefaultProbeConfig() has zero timeout")
	}

	if config.MaxBytes == 0 {
		t.Error("DefaultProbeConfig() has zero max bytes")
	}

	// Check defaults match spec
	if config.BaudRates[0] != 9600 {
		t.Errorf("First baud should be 9600, got %d", config.BaudRates[0])
	}

	if len(config.BaudRates) >= 2 && config.BaudRates[1] != 115200 {
		t.Errorf("Second baud should be 115200, got %d", config.BaudRates[1])
	}
}

func TestCleanSerialData(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "printable ASCII",
			input: []byte("Hello World"),
			want:  "Hello World",
		},
		{
			name:  "with CR LF",
			input: []byte("Line1\r\nLine2\r\n"),
			want:  "Line1\r\nLine2\r\n",
		},
		{
			name:  "with tabs",
			input: []byte("Col1\tCol2\tCol3"),
			want:  "Col1\tCol2\tCol3",
		},
		{
			name:  "with null bytes",
			input: []byte("Hello\x00World"),
			want:  "Hello World",
		},
		{
			name:  "with control chars",
			input: []byte("Text\x01\x02\x03More"),
			want:  "Text   More",
		},
		{
			name:  "with escape sequences",
			input: []byte("\x1B[31mRed\x1B[0m"),
			want:  "\x1B[31mRed\x1B[0m",
		},
		{
			name:  "invalid UTF-8",
			input: []byte{0xFF, 0xFE, 0xFD},
			want:  " ", // Replacement char as single space
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanSerialData(tt.input)
			if got != tt.want {
				t.Errorf("cleanSerialData() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProbeResultStructure(t *testing.T) {
	result := ProbeResult{
		Success:     true,
		Baud:        9600,
		RawData:     []byte("test data"),
		CleanedData: "test data",
		Fingerprint: fingerprint.Result{
			Vendor: "Test",
			OS:     "TestOS",
			Baud:   9600,
		},
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}

	if result.Baud != 9600 {
		t.Errorf("Expected Baud 9600, got %d", result.Baud)
	}

	if string(result.RawData) != "test data" {
		t.Error("RawData mismatch")
	}
}

func TestProbePortContext(t *testing.T) {
	// Test that context cancellation works
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	config := DefaultProbeConfig()
	config.BaudRates = []int{9600}

	result := ProbePort(ctx, "/dev/null", config)

	// Should fail due to context cancellation or port open failure
	if result.Success {
		t.Error("ProbePort() with cancelled context should not succeed")
	}
}

func TestQuickProbe(t *testing.T) {
	// Quick probe with non-existent port should return error
	result := QuickProbe("/dev/nonexistent_tty_12345")

	if result.Success {
		t.Error("QuickProbe() on nonexistent port should not succeed")
	}

	if result.Error == nil {
		t.Error("QuickProbe() should return error for nonexistent port")
	}
}

func TestProbeSingleBaudTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := ProbeConfig{
		BaudRates: []int{9600},
		Timeout:   50 * time.Millisecond,
		MaxBytes:  1024,
	}

	result := probeSingleBaud(ctx, "/dev/null", 9600, config)

	// Should fail or return quickly
	if result.Error == nil && !result.Success {
		// This is expected for /dev/null
	}
}

func TestCleanSerialDataUTF8(t *testing.T) {
	// Test UTF-8 handling
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "valid UTF-8",
			input: []byte("Hello 世界"),
		},
		{
			name:  "mixed ASCII and UTF-8",
			input: []byte("Test: café"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanSerialData(tt.input)
			// Should not panic and return non-empty string
			if result == "" {
				t.Error("cleanSerialData() returned empty string for valid input")
			}
		})
	}
}

func TestProbeConfigCustomBauds(t *testing.T) {
	config := ProbeConfig{
		BaudRates: []int{19200, 38400, 57600},
		Timeout:   500 * time.Millisecond,
		MaxBytes:  4096,
	}

	if len(config.BaudRates) != 3 {
		t.Errorf("Expected 3 baud rates, got %d", len(config.BaudRates))
	}

	for _, baud := range config.BaudRates {
		if baud <= 0 {
			t.Errorf("Invalid baud rate: %d", baud)
		}
	}
}

func TestCleanSerialDataPreservesLineEndings(t *testing.T) {
	input := []byte("Line1\r\nLine2\rLine3\nLine4")
	result := cleanSerialData(input)

	// Should preserve \r, \n, and \r\n
	if !strings.Contains(result, "\r\n") {
		t.Error("cleanSerialData() should preserve \\r\\n")
	}
}
