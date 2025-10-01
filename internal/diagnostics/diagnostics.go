package diagnostics

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	netpkg "github.com/alexpitcher/LanAudit/internal/net"
	"github.com/alexpitcher/LanAudit/internal/store"
)

// Result contains diagnostics test results
type Result struct {
	LinkUp      bool
	Gateway     string
	Ping        PingResult
	DNS         DNSResult
	HTTPS       HTTPSResult
	Suggestions []string
}

// PingResult contains ping test results
type PingResult struct {
	Loss      float64
	MedianRTT time.Duration
	Err       string
}

// DNSResult contains DNS test results
type DNSResult struct {
	SystemOK  bool
	AltOK     bool
	AltTried  []string
	Err       string
}

// HTTPSResult contains HTTPS test results
type HTTPSResult struct {
	OK     bool
	Status int
	TLSOK  bool
	Err    string
}

// Pinger interface for testing
type Pinger interface {
	Ping(ctx context.Context, host string, count int) (PingResult, error)
}

// DNSResolver interface for testing
type DNSResolver interface {
	ResolveSystem(ctx context.Context, host string) error
	ResolveAlt(ctx context.Context, host string, servers []string) error
}

// HTTPSProber interface for testing
type HTTPSProber interface {
	ProbeHTTPS(ctx context.Context, url string) (HTTPSResult, error)
}

// DefaultPinger implements the Pinger interface
type DefaultPinger struct{}

// DefaultDNSResolver implements the DNSResolver interface
type DefaultDNSResolver struct{}

// DefaultHTTPSProber implements the HTTPSProber interface
type DefaultHTTPSProber struct{}

// Run executes all diagnostic tests
func Run(ctx context.Context, details *netpkg.InterfaceDetails, config *store.Config) (*Result, error) {
	pinger := &DefaultPinger{}
	resolver := &DefaultDNSResolver{}
	prober := &DefaultHTTPSProber{}

	return RunWithDeps(ctx, details, config, pinger, resolver, prober)
}

// RunWithDeps runs diagnostics with injected dependencies for testing
func RunWithDeps(ctx context.Context, details *netpkg.InterfaceDetails, config *store.Config, pinger Pinger, resolver DNSResolver, prober HTTPSProber) (*Result, error) {
	result := &Result{
		LinkUp:  details.LinkUp,
		Gateway: details.DefaultGateway,
	}

	// Check link status
	if !details.LinkUp {
		result.Suggestions = append(result.Suggestions, "Interface is down. Check physical connection or bring interface up.")
		return result, nil
	}

	// Ping gateway
	if details.DefaultGateway != "" {
		pingRes, err := pinger.Ping(ctx, details.DefaultGateway, 4)
		if err != nil {
			result.Ping.Err = err.Error()
		} else {
			result.Ping = pingRes
		}

		if result.Ping.Loss > 50 {
			result.Suggestions = append(result.Suggestions, "High packet loss to gateway. Check network cable or Wi-Fi signal strength.")
		} else if result.Ping.Loss > 0 {
			result.Suggestions = append(result.Suggestions, "Some packet loss detected. Network may be congested.")
		}
	} else {
		result.Suggestions = append(result.Suggestions, "No default gateway configured. Check DHCP or static IP configuration.")
	}

	// DNS tests
	dnsErr := resolver.ResolveSystem(ctx, "example.com")
	result.DNS.SystemOK = dnsErr == nil
	if dnsErr != nil {
		result.DNS.Err = dnsErr.Error()
	}

	// Try alternative DNS servers if system DNS fails
	if !result.DNS.SystemOK && len(config.DNSAlternates) > 0 {
		altErr := resolver.ResolveAlt(ctx, "example.com", config.DNSAlternates)
		result.DNS.AltOK = altErr == nil
		result.DNS.AltTried = config.DNSAlternates

		if result.DNS.AltOK {
			result.Suggestions = append(result.Suggestions, fmt.Sprintf("System DNS failed but alternative DNS (%s) worked. Consider changing DNS servers.", config.DNSAlternates[0]))
		}
	}

	if !result.DNS.SystemOK && !result.DNS.AltOK {
		if result.Ping.Loss == 0 {
			result.Suggestions = append(result.Suggestions, "Gateway reachable but DNS resolution failing. Check DNS server configuration.")
		} else {
			result.Suggestions = append(result.Suggestions, "DNS and gateway connectivity issues. Try DHCP renew.")
		}
	}

	// HTTPS probe
	httpsRes, err := prober.ProbeHTTPS(ctx, "https://example.com")
	if err != nil {
		result.HTTPS.Err = err.Error()
	} else {
		result.HTTPS = httpsRes
	}

	if !result.HTTPS.OK && result.Ping.Loss == 0 && result.DNS.SystemOK {
		result.Suggestions = append(result.Suggestions, "Network connectivity OK but HTTPS failing. Check for proxy, firewall, or captive portal.")
	}

	if len(result.Suggestions) == 0 && result.HTTPS.OK {
		result.Suggestions = append(result.Suggestions, "All diagnostics passed. Network connectivity is healthy.")
	}

	return result, nil
}

// Ping executes ping command (macOS implementation)
func (p *DefaultPinger) Ping(ctx context.Context, host string, count int) (PingResult, error) {
	cmd := exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(count), "-W", "1000", host)
	output, err := cmd.Output()
	if err != nil {
		return PingResult{Err: err.Error()}, err
	}

	return parsePingOutput(string(output))
}

// parsePingOutput extracts ping statistics from command output
func parsePingOutput(output string) (PingResult, error) {
	result := PingResult{}

	// Extract packet loss
	lossRe := regexp.MustCompile(`(\d+\.?\d*)% packet loss`)
	if matches := lossRe.FindStringSubmatch(output); len(matches) >= 2 {
		loss, _ := strconv.ParseFloat(matches[1], 64)
		result.Loss = loss
	}

	// Extract RTT (use avg as median approximation)
	rttRe := regexp.MustCompile(`min/avg/max/stddev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms`)
	if matches := rttRe.FindStringSubmatch(output); len(matches) >= 3 {
		avg, _ := strconv.ParseFloat(matches[2], 64)
		result.MedianRTT = time.Duration(avg * float64(time.Millisecond))
	}

	return result, nil
}

// ResolveSystem performs DNS resolution using system resolver
func (r *DefaultDNSResolver) ResolveSystem(ctx context.Context, host string) error {
	resolver := &net.Resolver{}
	_, err := resolver.LookupHost(ctx, host)
	return err
}

// ResolveAlt performs DNS resolution using alternative DNS servers
func (r *DefaultDNSResolver) ResolveAlt(ctx context.Context, host string, servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("no alternative DNS servers provided")
	}

	client := &dns.Client{
		Timeout: 2 * time.Second,
	}

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)

	for _, server := range servers {
		serverAddr := server
		if !strings.Contains(serverAddr, ":") {
			serverAddr = serverAddr + ":53"
		}

		resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			return nil
		}
	}

	return fmt.Errorf("all alternative DNS servers failed")
}

// ProbeHTTPS performs HTTPS connectivity test
func (p *DefaultHTTPSProber) ProbeHTTPS(ctx context.Context, url string) (HTTPSResult, error) {
	result := HTTPSResult{TLSOK: true}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Err = err.Error()
		return result, err
	}

	resp, err := client.Do(req)
	if err != nil {
		result.Err = err.Error()
		if strings.Contains(err.Error(), "certificate") {
			result.TLSOK = false
		}
		return result, err
	}
	defer resp.Body.Close()

	result.OK = true
	result.Status = resp.StatusCode

	return result, nil
}
