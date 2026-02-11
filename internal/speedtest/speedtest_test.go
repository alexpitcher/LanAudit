package speedtest

import (
	"testing"
	"time"

	"github.com/showwin/speedtest-go/speedtest"
)

func TestResult(t *testing.T) {
	result := &Result{
		DownloadMbps: 100.5,
		UploadMbps:   50.2,
		Latency:      10 * time.Millisecond,
		Jitter:       2 * time.Millisecond,
		ServerName:   "Test Server",
		ServerCity:   "Test City",
		ServerHost:   "speedtest.example.com",
		Distance:     25.5,
		IsStub:       false,
	}

	if result.DownloadMbps != 100.5 {
		t.Errorf("Expected DownloadMbps 100.5, got %f", result.DownloadMbps)
	}

	if result.UploadMbps != 50.2 {
		t.Errorf("Expected UploadMbps 50.2, got %f", result.UploadMbps)
	}

	if result.IsStub {
		t.Error("Expected IsStub to be false")
	}
}

func TestStatus(t *testing.T) {
	status := Status()
	if status == "" {
		t.Error("Status() should return non-empty string")
	}
}

func TestFormatResult(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{
			name: "stub result",
			result: Result{
				IsStub: true,
			},
			want: "Speedtest not available (stub mode)",
		},
		{
			name: "real result",
			result: Result{
				DownloadMbps: 100.0,
				UploadMbps:   50.0,
				Latency:      10 * time.Millisecond,
				Jitter:       2 * time.Millisecond,
				ServerName:   "Test",
				ServerCity:   "City",
				Distance:     25.0,
				IsStub:       false,
			},
			want: "", // Just check it doesn't panic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatResult(&tt.result)
			if tt.want != "" && got != tt.want {
				t.Errorf("FormatResult() = %v, want %v", got, tt.want)
			}
			if got == "" {
				t.Error("FormatResult() returned empty string")
			}
		})
	}
}

func TestCalculateJitter(t *testing.T) {
	// calculateJitter is unexported but accessible since we are in package speedtest
	server := &speedtest.Server{
		Latency: 100 * time.Millisecond,
	}

	got := calculateJitter(server)
	want := 10 * time.Millisecond

	if got != want {
		t.Errorf("calculateJitter() = %v, want %v", got, want)
	}
}
