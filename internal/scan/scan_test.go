package scan

import (
	"testing"
	"time"
)

func TestExpandSubnet(t *testing.T) {
	tests := []struct {
		name        string
		gateway     string
		wantCount   int
		wantError   bool
		wantContain string
	}{
		{
			name:        "valid IPv4",
			gateway:     "192.168.1.1",
			wantCount:   254,
			wantError:   false,
			wantContain: "192.168.1.100",
		},
		{
			name:      "invalid IP",
			gateway:   "invalid",
			wantCount: 0,
			wantError: true,
		},
		{
			name:      "IPv6 not supported",
			gateway:   "::1",
			wantCount: 0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, err := expandSubnet(tt.gateway)

			if (err != nil) != tt.wantError {
				t.Errorf("expandSubnet() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if len(hosts) != tt.wantCount {
					t.Errorf("expandSubnet() returned %d hosts, want %d", len(hosts), tt.wantCount)
				}

				if tt.wantContain != "" {
					found := false
					for _, h := range hosts {
						if h == tt.wantContain {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expandSubnet() result does not contain %s", tt.wantContain)
					}
				}
			}
		})
	}
}

func TestGetServiceName(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{3306, "MySQL"},
		{9999, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getServiceName(tt.port)
			if got != tt.want {
				t.Errorf("getServiceName(%d) = %s, want %s", tt.port, got, tt.want)
			}
		})
	}
}

func TestTLSVersionToString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{0x0301, "1.0"},
		{0x0302, "1.1"},
		{0x0303, "1.2"},
		{0x0304, "1.3"},
		{0x0000, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tlsVersionToString(tt.version)
			if got != tt.want {
				t.Errorf("tlsVersionToString(0x%04x) = %s, want %s", tt.version, got, tt.want)
			}
		})
	}
}

func TestServiceInfo(t *testing.T) {
	service := ServiceInfo{
		Port:     443,
		Protocol: "tcp",
		State:    "open",
		Service:  "HTTPS",
		TLSInfo:  "TLS 1.3",
	}

	if service.State != "open" {
		t.Errorf("Expected State 'open', got %s", service.State)
	}

	if service.Service != "HTTPS" {
		t.Errorf("Expected Service 'HTTPS', got %s", service.Service)
	}
}

func TestStatus(t *testing.T) {
	status := Status()
	if status == "" {
		t.Error("Status() should return non-empty string")
	}
}

func TestScanPortTimeout(t *testing.T) {
	// Test scanning a port that definitely won't respond
	service := scanPort("240.0.0.1", 9999, 100*time.Millisecond)

	if service.State != "closed" {
		t.Errorf("Expected State 'closed' for unreachable host, got %s", service.State)
	}
}
