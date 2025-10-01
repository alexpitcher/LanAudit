package diagnostics

import (
	"context"
	"testing"
	"time"

	netpkg "github.com/alexpitcher/LanAudit/internal/net"
	"github.com/alexpitcher/LanAudit/internal/store"
)

// Mock implementations for testing
type mockPinger struct {
	result PingResult
	err    error
}

func (m *mockPinger) Ping(ctx context.Context, host string, count int) (PingResult, error) {
	return m.result, m.err
}

type mockDNSResolver struct {
	systemErr error
	altErr    error
}

func (m *mockDNSResolver) ResolveSystem(ctx context.Context, host string) error {
	return m.systemErr
}

func (m *mockDNSResolver) ResolveAlt(ctx context.Context, host string, servers []string) error {
	return m.altErr
}

type mockHTTPSProber struct {
	result HTTPSResult
	err    error
}

func (m *mockHTTPSProber) ProbeHTTPS(ctx context.Context, url string) (HTTPSResult, error) {
	return m.result, m.err
}

func TestParsePingOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantLoss   float64
		wantRTT    time.Duration
	}{
		{
			name: "successful ping",
			output: `PING 192.168.1.1 (192.168.1.1): 56 data bytes
64 bytes from 192.168.1.1: icmp_seq=0 ttl=64 time=1.234 ms
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.345 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=1.567 ms
64 bytes from 192.168.1.1: icmp_seq=3 ttl=64 time=1.890 ms

--- 192.168.1.1 ping statistics ---
4 packets transmitted, 4 received, 0.0% packet loss, time 3005ms
rtt min/avg/max/stddev = 1.234/1.759/2.345/0.456 ms`,
			wantLoss: 0.0,
			wantRTT:  1759 * time.Microsecond,
		},
		{
			name: "partial loss",
			output: `--- 192.168.1.1 ping statistics ---
4 packets transmitted, 2 received, 50.0% packet loss, time 3005ms
rtt min/avg/max/stddev = 1.234/2.500/3.456/1.111 ms`,
			wantLoss: 50.0,
			wantRTT:  2500 * time.Microsecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePingOutput(tt.output)
			if err != nil {
				t.Fatalf("parsePingOutput() error = %v", err)
			}
			if result.Loss != tt.wantLoss {
				t.Errorf("Loss = %v, want %v", result.Loss, tt.wantLoss)
			}
			if result.MedianRTT != tt.wantRTT {
				t.Errorf("MedianRTT = %v, want %v", result.MedianRTT, tt.wantRTT)
			}
		})
	}
}

func TestRunWithDeps(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name            string
		details         *netpkg.InterfaceDetails
		pinger          Pinger
		resolver        DNSResolver
		prober          HTTPSProber
		wantSuggestions int
	}{
		{
			name: "all healthy",
			details: &netpkg.InterfaceDetails{
				LinkUp:         true,
				DefaultGateway: "192.168.1.1",
			},
			pinger:          &mockPinger{result: PingResult{Loss: 0, MedianRTT: 1 * time.Millisecond}},
			resolver:        &mockDNSResolver{systemErr: nil, altErr: nil},
			prober:          &mockHTTPSProber{result: HTTPSResult{OK: true, Status: 200, TLSOK: true}},
			wantSuggestions: 1,
		},
		{
			name: "link down",
			details: &netpkg.InterfaceDetails{
				LinkUp:         false,
				DefaultGateway: "192.168.1.1",
			},
			pinger:          &mockPinger{},
			resolver:        &mockDNSResolver{},
			prober:          &mockHTTPSProber{},
			wantSuggestions: 1,
		},
		{
			name: "high packet loss",
			details: &netpkg.InterfaceDetails{
				LinkUp:         true,
				DefaultGateway: "192.168.1.1",
			},
			pinger:          &mockPinger{result: PingResult{Loss: 75}},
			resolver:        &mockDNSResolver{systemErr: nil},
			prober:          &mockHTTPSProber{result: HTTPSResult{OK: true}},
			wantSuggestions: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &store.Config{
				DNSAlternates: []string{"1.1.1.1", "8.8.8.8"},
			}

			result, err := RunWithDeps(ctx, tt.details, config, tt.pinger, tt.resolver, tt.prober)
			if err != nil {
				t.Fatalf("RunWithDeps() error = %v", err)
			}

			if len(result.Suggestions) < tt.wantSuggestions {
				t.Errorf("got %d suggestions, want at least %d. Suggestions: %v",
					len(result.Suggestions), tt.wantSuggestions, result.Suggestions)
			}
		})
	}
}
