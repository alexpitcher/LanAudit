package scan

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/alexpitcher/LanAudit/internal/consent"
)

// ServiceInfo represents a discovered service on a host
type ServiceInfo struct {
	Port     int
	Protocol string
	State    string
	Service  string
	TLSInfo  string
	Banner   string
}

// HostResult represents scan results for a single host
type HostResult struct {
	IP       string
	Hostname string
	Latency  time.Duration
	Services []ServiceInfo
	Error    error
}

// ScanResult represents the complete gateway audit results
type ScanResult struct {
	Gateway     string
	Hosts       []HostResult
	StartTime   time.Time
	EndTime     time.Time
	TotalHosts  int
	ActiveHosts int
}

// CommonPorts defines frequently-used ports to scan
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443,
}

// AuditGateway performs a network scan of the gateway subnet
// This requires explicit user consent via the SCAN-YES token
func AuditGateway(gateway string, ports []int, timeout time.Duration) (*ScanResult, error) {
	// Require explicit consent
	if err := consent.Confirm("SCAN-YES", "SCAN-YES"); err != nil {
		return nil, fmt.Errorf("gateway audit requires consent: %w", err)
	}

	consent.Log(fmt.Sprintf("Gateway audit started on %s", gateway), map[string]string{
		"gateway": gateway,
	})

	if len(ports) == 0 {
		ports = CommonPorts
	}

	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	result := &ScanResult{
		Gateway:   gateway,
		StartTime: time.Now(),
		Hosts:     make([]HostResult, 0),
	}

	// Parse gateway to determine subnet
	hosts, err := expandSubnet(gateway)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway: %w", err)
	}

	result.TotalHosts = len(hosts)

	// Scan hosts concurrently with a worker pool
	var wg sync.WaitGroup
	hostChan := make(chan string, len(hosts))
	resultChan := make(chan HostResult, len(hosts))

	// Start workers
	numWorkers := 50
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range hostChan {
				hostResult := scanHost(host, ports, timeout)
				resultChan <- hostResult
			}
		}()
	}

	// Send hosts to workers
	go func() {
		for _, host := range hosts {
			hostChan <- host
		}
		close(hostChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for hostResult := range resultChan {
		if hostResult.Error == nil && len(hostResult.Services) > 0 {
			result.ActiveHosts++
		}
		result.Hosts = append(result.Hosts, hostResult)
	}

	result.EndTime = time.Now()

	consent.Log(fmt.Sprintf("Gateway audit completed: %d active hosts found", result.ActiveHosts), map[string]string{
		"active_hosts": fmt.Sprintf("%d", result.ActiveHosts),
		"total_hosts":  fmt.Sprintf("%d", result.TotalHosts),
	})

	return result, nil
}

// expandSubnet converts a gateway IP to a list of hosts to scan
func expandSubnet(gateway string) ([]string, error) {
	// Parse IP and determine /24 subnet
	ip := net.ParseIP(gateway)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", gateway)
	}

	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 not supported yet")
	}

	// Generate /24 subnet (254 hosts)
	hosts := make([]string, 0, 254)
	baseIP := fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])

	for i := 1; i <= 254; i++ {
		hosts = append(hosts, fmt.Sprintf("%s%d", baseIP, i))
	}

	return hosts, nil
}

// scanHost performs a port scan on a single host
func scanHost(host string, ports []int, timeout time.Duration) HostResult {
	result := HostResult{
		IP:       host,
		Services: make([]ServiceInfo, 0),
	}

	// Quick ping check first
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", host), timeout)
	if err == nil {
		conn.Close()
		result.Latency = time.Since(start)
	} else {
		// Try one more port to confirm host is down
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:443", host), timeout)
		if err != nil {
			// Host appears down, skip detailed scan
			return result
		}
		conn.Close()
		result.Latency = time.Since(start)
	}

	// Reverse DNS lookup
	names, err := net.LookupAddr(host)
	if err == nil && len(names) > 0 {
		result.Hostname = strings.TrimSuffix(names[0], ".")
	}

	// Scan each port
	for _, port := range ports {
		service := scanPort(host, port, timeout)
		if service.State == "open" {
			result.Services = append(result.Services, service)
		}
	}

	return result
}

// scanPort checks if a specific port is open and gathers service info
func scanPort(host string, port int, timeout time.Duration) ServiceInfo {
	service := ServiceInfo{
		Port:     port,
		Protocol: "tcp",
		State:    "closed",
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return service
	}
	defer conn.Close()

	service.State = "open"
	service.Service = getServiceName(port)

	// Try TLS handshake for common TLS ports
	if port == 443 || port == 8443 || port == 22 {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		tlsConn.SetDeadline(time.Now().Add(timeout))

		err = tlsConn.Handshake()
		if err == nil {
			state := tlsConn.ConnectionState()
			service.TLSInfo = fmt.Sprintf("TLS %s", tlsVersionToString(state.Version))
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				service.TLSInfo += fmt.Sprintf(" (CN: %s)", cert.Subject.CommonName)
			}
		}
		tlsConn.Close()
	}

	return service
}

// getServiceName returns the common service name for a port
func getServiceName(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		5900: "VNC",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	}

	if name, ok := services[port]; ok {
		return name
	}
	return "Unknown"
}

// tlsVersionToString converts TLS version constant to string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
		return "Unknown"
	}
}

// Status returns information about the last scan
func Status() string {
	return "Gateway audit requires SCAN-YES consent"
}
