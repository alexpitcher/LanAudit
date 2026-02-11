package logging

import (
	"bytes"
	"log"
	"os"
	"testing"
)

func TestLogging(t *testing.T) {
	// Capture output
	var buf bytes.Buffer

	// Override logger for testing
	// ensureLogger will be called by logf, so we need to mock or reset logic if we want to test ensureLogger
	// But `logger` is a package-level var. We can set it directly.
	// Ensure logger is initialized so strict initialization doesn't overwrite our mock
	ensureLogger()
	originalLogger := logger
	defer func() { logger = originalLogger }()
	logger = log.New(&buf, "", 0)

	tests := []struct {
		name    string
		logFunc func(string, ...interface{})
		level   string
		message string
		want    string
	}{
		{
			name:    "Info",
			logFunc: Infof,
			level:   "INFO",
			message: "test message",
			want:    "[INFO] test message\n",
		},
		{
			name:    "Warn",
			logFunc: Warnf,
			level:   "WARN",
			message: "warning happened",
			want:    "[WARN] warning happened\n",
		},
		{
			name:    "Error",
			logFunc: Errorf,
			level:   "ERROR",
			message: "error occurred",
			want:    "[ERROR] error occurred\n",
		},
		{
			name:    "Debug",
			logFunc: Debugf,
			level:   "DEBUG",
			message: "debug info",
			want:    "[DEBUG] debug info\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message)
			got := buf.String()
			if got != tt.want {
				t.Errorf("%s() output = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestInitLogger(t *testing.T) {
	// We can't easily test initLogger without side effects (file creation),
	// but we can verify it doesn't panic.
	// We save and restore the original logger to avoid messing up other tests.
	originalLogger := logger
	defer func() { logger = originalLogger }()

	// Reset sync.Once to allow re-initialization (hacky, using reflect or just assuming it runs once)
	// Actually, `once` is private. We can't reset it.
	// So we just call ensureLogger() and make sure `logger` is not nil.
	ensureLogger()
	if logger == nil {
		t.Error("logger should be initialized")
	}

	// Verify log file exists
	if _, err := os.Stat("log.txt"); os.IsNotExist(err) {
		t.Error("log.txt should be created")
	}
}
