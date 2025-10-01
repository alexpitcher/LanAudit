# LanAudit

**LanAudit** — Terminal UI for network diagnostics, VLAN testing, and cable analysis.

A cross-platform (macOS first) terminal-based network diagnostics tool designed for ethical network administration and troubleshooting.

## Features

- **Interactive Terminal UI** - Bubbletea-powered interface with tabbed navigation
- **Interface Selection** - Mandatory interface picker at startup
- **Network Details** - View IPs, MAC, MTU, gateway, DNS servers with auto-refresh
- **Diagnostics Suite**
  - Link status checking
  - Gateway ping tests (packet loss and latency)
  - DNS resolution testing (system + alternative servers)
  - HTTPS connectivity probes with TLS verification
  - Intelligent suggestions based on test results
- **VLAN Testing** (macOS) - Create ephemeral VLAN interfaces, test DHCP, automatic cleanup
- **Consent Logging** - All disruptive actions logged with explicit user consent required
- **Snapshots** - Export network state to JSON with optional redaction of sensitive data
- **Settings** - Configure DNS servers, timeouts, and privacy options
- **Packet Capture** - Live packet capture with BPF filtering (requires root)
- **Gateway Audit** - Network scanning and port enumeration with consent
- **Speed Test** - Internet speed testing using speedtest.net
- **LLDP Discovery** - Passive LLDP neighbor discovery
- **Serial Console** - Full serial console with baud probing and device fingerprinting

## Quick Start (macOS)

### Build Instructions

**Requirements:** Go 1.22+

```bash
# Clone the repository
git clone https://github.com/alexpitcher/LanAudit.git
cd LanAudit

# Build the binary
make build

# Run the TUI
make run

# Or run directly
./bin/lanaudit
```

### Usage

```bash
# Interactive TUI mode (default)
./bin/lanaudit

# Select specific interface
./bin/lanaudit --iface en0

# Headless mode (JSON output)
./bin/lanaudit --headless --iface en0

# Show version
./bin/lanaudit --version
```

### Keyboard Navigation

In the TUI:
- **ENTER** - Auto-select first physical interface
- **d** - Details view
- **g** - Diagnostics view
- **v** - VLAN tester (requires sudo)
- **n** - Snapshots
- **s** - Settings
- **c** - Packet Capture (requires root)
- **a** - Gateway Audit (requires consent)
- **p** - Speedtest
- **o** - Serial Console
- **q** - Quit

## Permissions

### Standard Features
Most features work without elevated privileges:
- Interface listing
- Network details
- DNS testing
- HTTPS probes

### Root/Sudo Required
Some features require elevated privileges:
- **VLAN Testing** - Creating virtual network interfaces
- **Packet Capture** - Raw socket access (coming soon)
- **Some Diagnostics** - ICMP ping on some systems

Run with sudo when needed:
```bash
sudo ./bin/lanaudit
```

## Configuration

Configuration is stored in `~/.lanaudit/config.json`:

```json
{
  "dns_alternates": ["1.1.1.1", "8.8.8.8"],
  "diagnostics_timeout_ms": 1500,
  "redact": false,
  "console": {
    "default_bauds": [9600, 115200],
    "crlf_mode": "CRLF",
    "local_echo": false,
    "log_by_default": false,
    "break_ms": 250
  }
}
```

### Consent Logging

Disruptive actions are logged to `~/.lanaudit/consent.log`:
```
2025-01-15T10:30:00Z | VLAN_TEST | physical_interface=en0 vlans=[100,200] keep=false
```

### Snapshots

Snapshots are saved to `~/.lanaudit/snaps/` with an index file for quick reference.

## Serial Console

The Serial Console feature provides full serial port access for network equipment, routers, switches, and embedded devices.

### Features
- **Auto-discovery** - Finds USB serial adapters, excluding Bluetooth and debug ports
- **Baud probing** - Tests 9600 and 115200 automatically
- **Advanced fingerprinting** - Multi-stage engine recognises banners, prompts, and bootloaders for Cisco, Juniper, Aruba, MikroTik, Fortinet, Palo Alto, Huawei, Dell, VyOS, OpenWrt, pfSense, and more
- **Safe probes** - Runs guarded, read-only vendor commands (e.g., `show version`, `/system resource print`) to confirm identity and extract models
- **Live console** - Full keystroke passthrough with scrollback
- **Break signal** - Send BREAK with configurable duration
- **DTR/RTS control** - Toggle control lines
- **CR/LF modes** - Support for CRLF, CR, or LF line endings
- **Transcript logging** - Save session to `~/.lanaudit/console/`
- **Snapshot integration** - Include console session summary in snapshots

#### How detection works
- Console RX is normalised (ANSI stripped, CR/LF harmonised) and classified into **pre-login**, **login**, **prompt**, or **bootloader** stages.
- Static signatures score banners, login prompts, and CLI prompts; evidence is deduplicated with confidence scoring.
- When a safe prompt is detected, a guarded probe (e.g., `show version`) can be issued to collect model strings—config-mode prompts are skipped unless explicitly allowed.
- Results include vendor, OS, detected model, stage, baud, and the top evidence lines; evidence is redacted in snapshots if `redact` is enabled.

#### Console configuration
Configuration is stored in `~/.lanaudit/config.json`:

```json
{
  "console": {
    "default_bauds": [9600, 115200],
    "crlf_mode": "CRLF",
    "local_echo": false,
    "log_by_default": false,
    "break_ms": 250,
    "allow_probe_in_config_mode": false
  }
}
```

Toggle `allow_probe_in_config_mode` (or press `A` in the console view) if you explicitly want to run safe probes while the prompt is in configuration mode.

### Supported Devices
The fingerprinting system recognizes:
- Cisco IOS, IOS-XE, and switches
- Aruba AOS-CX and Aruba Instant
- U-Boot bootloaders
- BusyBox/Linux systems
- Juniper JUNOS
- Proxmox/GRUB
- MikroTik RouterOS
- pfSense/FreeBSD
- OpenWrt

### Usage

**macOS:**
```bash
# Serial ports are typically /dev/cu.* or /dev/tty.*
# Press 'o' in TUI to access Console tab
```

**Linux:**
```bash
# Add user to dialout group for serial access
sudo usermod -a -G dialout $USER
# Log out and back in for changes to take effect

# Serial ports are typically /dev/ttyUSB* or /dev/ttyACM*
```

### Keyboard Commands (Console View)
- **p** - Probe selected port (detects baud and device type)
- **enter** - Open serial session
- **b** - Send BREAK signal
- **d** - Toggle DTR line
- **r** - Toggle RTS line
- **t** - Toggle transcript logging
- **e** - Toggle local echo
- **,** / **.** - Cycle CR/LF mode
- **x** - Close session
- **Ctrl+L** - Clear screen buffer
- **P** - Run a safe, read-only fingerprint probe against the current prompt
- **A** - Allow/deny safe probes while the prompt is in `(config...)` mode (default denied)

### Supported USB-to-Serial Chipsets
- FTDI (FT232, FT2232, etc.)
- Silicon Labs CP210x (CP2102, CP2104)
- CH340/CH341
- Prolific PL2303

### Troubleshooting

**macOS Permission Denied:**
```bash
# Check port exists
ls -l /dev/cu.*

# Run with sudo if needed
sudo ./bin/lanaudit
```

**Linux Permission Denied:**
```bash
# Check dialout group membership
groups $USER

# Add to dialout group (requires re-login)
sudo usermod -a -G dialout $USER
```

**No Ports Found:**
- Unplug and replug USB serial adapter
- Check `dmesg` (Linux) or Console.app (macOS) for driver messages
- Verify USB cable supports data (not charge-only)

**Garbled Output:**
- Try alternate baud rate (9600 or 115200)
- Adjust CR/LF mode (some devices need different line endings)
- Toggle local echo off if seeing double characters

## Development

```bash
# Run tests
make test

# Lint code
make lint

# Build for all platforms
make build-darwin build-linux

# Clean build artifacts
make clean
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/net/
go test ./internal/diagnostics/
go test ./internal/vlan/
```

## Architecture

```
LanAudit/
├── cmd/lanaudit/          # Main entry point
├── internal/
│   ├── tui/               # Bubbletea TUI implementation
│   ├── net/               # Network interface operations
│   ├── diagnostics/       # Connectivity tests
│   ├── vlan/              # VLAN testing (platform-specific)
│   ├── consent/           # User consent and logging
│   ├── store/             # Configuration and snapshots
│   ├── capture/           # Packet capture (stub)
│   ├── scan/              # Gateway audit (stub)
│   ├── speedtest/         # Speed testing (stub)
│   ├── ssh/               # SSH operations (stub)
│   ├── snmp/              # SNMP queries (stub)
│   └── llldp/             # LLDP discovery (stub)
└── Makefile
```

## Platform Support

| Feature | macOS | Linux | Status |
|---------|-------|-------|--------|
| Interface listing | ✅ | ✅ | Complete |
| Network details | ✅ | ✅ | Complete |
| Diagnostics | ✅ | ✅ | Complete |
| VLAN testing | ✅ | ❌ | macOS only |
| TUI | ✅ | ✅ | Complete |

## Roadmap

- [ ] Enhanced diagnostics with traceroute
- [ ] Packet capture integration
- [ ] Gateway security audit (authorized testing only)
- [ ] Network speed testing
- [ ] Switch-assisted cable diagnostics (TDR)
- [ ] LLDP/CDP neighbor discovery
- [ ] SSH connectivity testing
- [ ] SNMP device queries
- [ ] Linux VLAN support
- [ ] Windows support

## Disclaimer

⚠️ **ETHICAL USE ONLY**

**For use on networks you own or have explicit permission to test. No stealth features.**

This tool is intended for legitimate network administration, diagnostics, and troubleshooting on networks where you have proper authorization. LanAudit includes:

- Explicit consent requirements for disruptive operations
- Comprehensive logging of all actions
- No stealth or hidden functionality
- Clear warnings before running privileged operations

**Always obtain explicit permission before running network diagnostics or tests on any network you do not own.**

Unauthorized network scanning, testing, or interference may violate:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions

The authors and contributors of LanAudit assume no liability for misuse of this tool.

## License

Apache License 2.0 - See LICENSE file for details.

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

This project adheres to the Contributor Covenant Code of Conduct. By participating, you are expected to uphold this code.

## ASCII Art Preview

```
┌─ LanAudit ─ Interface Picker ─┐
│                                │
│ Select a network interface:    │
│                                │
│  1. en0                        │
│  2. en1                        │
│  3. lo0          (virtual)     │
│                                │
│ Press ENTER to auto-select     │
│ Press q to quit                │
└────────────────────────────────┘

[d] Details  [g] Diagnose  [v] VLAN  [n] Snap  [s] Settings  [c] Capture  [a] Audit  [p] Speedtest

Interface: en0
MAC: a4:83:e7:12:34:56
MTU: 1500
Link: true

IPs:
  - 192.168.1.100
  - fe80::a683:e7ff:fe12:3456

Gateway: 192.168.1.1
DNS Servers:
  - 192.168.1.1
  - 8.8.8.8

Last updated: 14:23:45

Interface: en0 | Viewing Details | q: quit
```

## Support

For issues, questions, or feature requests, please open an issue on GitHub:
https://github.com/alexpitcher/LanAudit/issues
