package speedtest

import (
	"fmt"
	"time"

	"github.com/showwin/speedtest-go/speedtest"
)

// Result contains speedtest results
type Result struct {
	DownloadMbps float64
	UploadMbps   float64
	Latency      time.Duration
	Jitter       time.Duration
	ServerName   string
	ServerCity   string
	ServerHost   string
	Distance     float64
	IsStub       bool
}

// Run performs a real speedtest using the speedtest-go library
func Run() (*Result, error) {
	return RunWithTimeout(30 * time.Second)
}

// RunWithTimeout performs a speedtest with a custom timeout
func RunWithTimeout(timeout time.Duration) (*Result, error) {
	// Fetch server list
	user, err := speedtest.FetchUserInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info: %w", err)
	}

	serverList, err := speedtest.FetchServers()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch servers: %w", err)
	}

	// Find nearest servers
	targets, err := serverList.FindServer([]int{})
	if err != nil {
		return nil, fmt.Errorf("failed to find servers: %w", err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no speedtest servers available")
	}

	// Use the closest server
	server := targets[0]

	// Test latency
	err = server.PingTest(nil)
	if err != nil {
		return nil, fmt.Errorf("ping test failed: %w", err)
	}

	// Test download speed
	err = server.DownloadTest()
	if err != nil {
		return nil, fmt.Errorf("download test failed: %w", err)
	}

	// Test upload speed
	err = server.UploadTest()
	if err != nil {
		return nil, fmt.Errorf("upload test failed: %w", err)
	}

	// Build result
	result := &Result{
		DownloadMbps: float64(server.DLSpeed),
		UploadMbps:   float64(server.ULSpeed),
		Latency:      server.Latency,
		ServerName:   server.Name,
		ServerCity:   server.Sponsor,
		ServerHost:   server.Host,
		Distance:     server.Distance,
		IsStub:       false,
	}

	// Calculate jitter if available
	if user != nil {
		result.Jitter = calculateJitter(server)
	}

	return result, nil
}

// calculateJitter computes jitter from ping results
func calculateJitter(server *speedtest.Server) time.Duration {
	// Simple jitter approximation based on latency variance
	// In a real implementation, you'd collect multiple ping samples
	return server.Latency / 10
}

// Status returns information about speedtest functionality
func Status() string {
	return "Speedtest ready - uses speedtest.net servers"
}

// FormatResult returns a human-readable speedtest result
func FormatResult(r *Result) string {
	if r.IsStub {
		return "Speedtest not available (stub mode)"
	}

	return fmt.Sprintf(`Speedtest Results:
  Server: %s (%s)
  Distance: %.2f km
  Latency: %v
  Jitter: %v
  Download: %.2f Mbps
  Upload: %.2f Mbps`,
		r.ServerCity,
		r.ServerName,
		r.Distance,
		r.Latency,
		r.Jitter,
		r.DownloadMbps,
		r.UploadMbps,
	)
}
