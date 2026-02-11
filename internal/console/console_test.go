package console

import (
	"testing"
)

func TestDefaultSessionConfig(t *testing.T) {
	cfg := DefaultSessionConfig("/dev/ttyUSB0", 9600)

	if cfg.PortPath != "/dev/ttyUSB0" {
		t.Errorf("Expected path /dev/ttyUSB0, got %s", cfg.PortPath)
	}
	if cfg.Baud != 9600 {
		t.Errorf("Expected baud 9600, got %d", cfg.Baud)
	}
	if cfg.DataBits != 8 {
		t.Errorf("Expected databits 8, got %d", cfg.DataBits)
	}
	if cfg.StopBits != 1 {
		t.Errorf("Expected stopbits 1, got %d", cfg.StopBits)
	}
}
