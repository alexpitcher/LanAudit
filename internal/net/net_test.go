package net

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseDefaultGateway(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name: "valid macOS route output",
			input: `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0`,
			want:    "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "no gateway found",
			input:   "some random output",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDefaultGateway(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDefaultGateway() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseDefaultGateway() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseScutilDNS(t *testing.T) {
	data, err := os.ReadFile("testdata/scutil_dns.txt")
	if err != nil {
		t.Fatalf("failed to read test data: %v", err)
	}

	dns := parseScutilDNS(string(data))

	if len(dns) < 2 {
		t.Errorf("expected at least 2 DNS servers, got %d", len(dns))
	}

	expected := map[string]bool{
		"192.168.1.1": true,
		"8.8.8.8":     true,
	}

	for _, server := range dns {
		if !expected[server] {
			t.Errorf("unexpected DNS server: %s", server)
		}
	}
}

func TestParseDNSFromResolvConf(t *testing.T) {
	testFile := filepath.Join("testdata", "resolv.conf")

	dns, err := parseDNSFromResolvConf(testFile)
	if err != nil {
		t.Fatalf("parseDNSFromResolvConf() error = %v", err)
	}

	expected := []string{"8.8.8.8", "1.1.1.1"}
	if len(dns) != len(expected) {
		t.Errorf("expected %d DNS servers, got %d", len(expected), len(dns))
	}

	for i, server := range dns {
		if server != expected[i] {
			t.Errorf("DNS server %d: got %s, want %s", i, server, expected[i])
		}
	}
}

func TestIsVirtualInterface(t *testing.T) {
	tests := []struct {
		name string
		mac  string
		want bool
	}{
		{"vlan1", "00:11:22:33:44:55", true},
		{"lo0", "", true},
		{"docker0", "02:42:ac:11:00:02", true},
		{"en0", "a4:83:e7:12:34:56", false},
		{"eth0", "00:50:56:c0:00:08", false},
		{"utun0", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isVirtualInterface(tt.name, tt.mac); got != tt.want {
				t.Errorf("isVirtualInterface(%s, %s) = %v, want %v", tt.name, tt.mac, got, tt.want)
			}
		})
	}
}

func TestListInterfaces(t *testing.T) {
	ifaces, err := ListInterfaces()
	if err != nil {
		t.Fatalf("ListInterfaces() error = %v", err)
	}

	if len(ifaces) == 0 {
		t.Error("expected at least one interface")
	}

	for _, iface := range ifaces {
		if iface.Name == "" {
			t.Error("interface name should not be empty")
		}
		if iface.MTU <= 0 {
			t.Errorf("interface %s has invalid MTU: %d", iface.Name, iface.MTU)
		}
	}
}
