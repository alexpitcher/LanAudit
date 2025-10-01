package fingerprint

import (
	"regexp"
	"strings"
)

// SafeProbe describes a guarded, read-only command used for device identification.
type SafeProbe struct {
	Name      string
	Command   string
	Expect    []*regexp.Regexp
	Scrape    []*regexp.Regexp
	Guard     *regexp.Regexp
	TimeoutMs int
}

func (sp *SafeProbe) Score(out string) float64 {
	if sp == nil {
		return 0
	}
	for _, re := range sp.Expect {
		if re.MatchString(out) {
			return 0.2
		}
	}
	return 0
}

func (sp *SafeProbe) ScrapeModel(out string) string {
	if sp == nil {
		return ""
	}
	for _, re := range sp.Scrape {
		if match := re.FindStringSubmatch(out); len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
	}
	return ""
}

func compileRegexps(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

var (
	guardCisco      = regexp.MustCompile(`(?m)^([A-Za-z0-9._-]+)(\((config[^\)]*)\))?[#>] ?$`)
	guardMikroTik   = regexp.MustCompile(`(?m)^\[[^\]]+\]\s?> ?$`)
	guardLinuxShell = regexp.MustCompile(`(?m)[$#] ?$`)
	guardJunos      = regexp.MustCompile(`(?m)^[\w\-]+@[\w\-.]+[>#] ?$`)
	guardHuawei     = regexp.MustCompile(`(?m)^(<[Hh][PpEe]?[^>]*>|\[[Hh].*?\])$`)
	guardComware    = regexp.MustCompile(`(?m)^((<|\[)HPE?.*?(>|\]))$`)
	guardVyOS       = regexp.MustCompile(`(?m)^vyos@.*[$#] ?$`)
	guardFGT        = regexp.MustCompile(`(?m)^FGT\w*\s?[#>] ?$`)
	guardPaloAlto   = regexp.MustCompile(`(?m)^[\w\-]+@PA-\w+[>#] ?$`)
)

var safeProbes = map[string]*SafeProbe{
	"Cisco:IOS": {
		Name:      "cisco_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`Cisco IOS Software`, `Configuration register`),
		Scrape:    compileRegexps(`(?m)^[Cc]isco (Catalyst|IOS|NX-OS).*?\b([A-Z0-9-]+)`, `(?m)^Processor board ID ([\w-]+)`),
		TimeoutMs: 1200,
	},
	"Cisco:IOS-XE": {
		Name:      "cisco_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`IOS[- ]XE`, `Cisco IOS Software`),
		Scrape:    compileRegexps(`(?m)^Cisco (\S+) Software`, `(?m)^cisco (\S+) \(`),
		TimeoutMs: 1200,
	},
	"Cisco:NX-OS": {
		Name:      "cisco_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`Nexus`, `NX-OS`),
		Scrape:    compileRegexps(`(?m)^Hardware\s+:\s+(.*)`),
		TimeoutMs: 1400,
	},
	"Cisco:IOS-XR": {
		Name:      "cisco_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`IOS XR`, `cisco IOS XR`),
		Scrape:    compileRegexps(`(?m)^cisco IOS XR Software, Version ([\w.\-]+)`),
		TimeoutMs: 1500,
	},
	"Cisco:ASA": {
		Name:      "cisco_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`Cisco Adaptive Security Appliance`, `ASA`),
		Scrape:    compileRegexps(`(?m)^Hardware\s+:\s+(.*)`),
		TimeoutMs: 1400,
	},
	"Juniper:JUNOS": {
		Name:      "junos_show_version",
		Command:   "show version",
		Guard:     guardJunos,
		Expect:    compileRegexps(`JUNOS`, `Model:`),
		Scrape:    compileRegexps(`(?m)^Model:\s+(\S+)`),
		TimeoutMs: 1500,
	},
	"Aruba:AOS-CX": {
		Name:      "aruba_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`ArubaOS-CX`, `Version`),
		Scrape:    compileRegexps(`(?m)^Platform :\s+(.*)`),
		TimeoutMs: 1500,
	},
	"Aruba:AOS-S": {
		Name:      "aruba_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`Aruba`, `Revision`),
		Scrape:    compileRegexps(`(?m)^ROM Version\s+:\s+(.*)`),
		TimeoutMs: 1500,
	},
	"MikroTik:RouterOS": {
		Name:      "mikrotik_resource_print",
		Command:   "/system resource print",
		Guard:     guardMikroTik,
		Expect:    compileRegexps(`(?i)routeros`, `(?i)uptime`),
		Scrape:    compileRegexps(`(?m)^board-name: (.*)`),
		TimeoutMs: 1200,
	},
	"Ubiquiti:EdgeOS": {
		Name:      "linux_uname",
		Command:   "uname -a",
		Guard:     guardLinuxShell,
		Expect:    compileRegexps(`Linux`, `EdgeRouter`),
		Scrape:    compileRegexps(`Linux (\S+)`),
		TimeoutMs: 1000,
	},
	"Linux/BusyBox:Linux": {
		Name:      "linux_uname",
		Command:   "uname -a",
		Guard:     guardLinuxShell,
		Expect:    compileRegexps(`Linux`, `version`),
		Scrape:    compileRegexps(`Linux (\S+)`),
		TimeoutMs: 1000,
	},
	"Fortinet:FortiOS": {
		Name:      "fortigate_get_system_status",
		Command:   "get system status",
		Guard:     guardFGT,
		Expect:    compileRegexps(`FortiGate`, `Version`),
		Scrape:    compileRegexps(`(?m)^Version: (.*)`),
		TimeoutMs: 1400,
	},
	"PaloAlto:PAN-OS": {
		Name:      "paloalto_show_system_info",
		Command:   "show system info",
		Guard:     guardPaloAlto,
		Expect:    compileRegexps(`system info`, `model`),
		Scrape:    compileRegexps(`(?m)^model:\s+(\S+)`),
		TimeoutMs: 1400,
	},
	"Huawei:VRP": {
		Name:      "huawei_display_version",
		Command:   "display version",
		Guard:     guardHuawei,
		Expect:    compileRegexps(`VRP`, `Huawei`),
		Scrape:    compileRegexps(`(?m)^Huawei Versatile Routing Platform Software\s+\(VRP\) (.*)`),
		TimeoutMs: 1800,
	},
	"HPE:Comware": {
		Name:      "hpe_display_version",
		Command:   "display version",
		Guard:     guardComware,
		Expect:    compileRegexps(`Comware`, `System Description`),
		Scrape:    compileRegexps(`(?m)^HP Comware Platform Software, Version (.*)`),
		TimeoutMs: 1600,
	},
	"Dell:OS10": {
		Name:      "dell_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`Dell EMC Networking OS10`, `OS10`),
		Scrape:    compileRegexps(`(?m)^Product:\s+(.*)`),
		TimeoutMs: 1600,
	},
	"Brocade/Extreme:FastIron": {
		Name:      "brocade_show_version",
		Command:   "show version",
		Guard:     guardCisco,
		Expect:    compileRegexps(`FastIron`, `ICX`),
		Scrape:    compileRegexps(`(?m)^System Model:\s+(.*)`),
		TimeoutMs: 1600,
	},
	"VyOS:VyOS": {
		Name:      "vyos_show_version",
		Command:   "show version",
		Guard:     guardVyOS,
		Expect:    compileRegexps(`VyOS`, `Version`),
		Scrape:    compileRegexps(`(?m)^Version: (.*)`),
		TimeoutMs: 1400,
	},
	"OpenWrt:OpenWrt": {
		Name:      "openwrt_release",
		Command:   "cat /etc/openwrt_release || uname -a",
		Guard:     guardLinuxShell,
		Expect:    compileRegexps(`OpenWrt`, `DISTRIB_ID`),
		Scrape:    compileRegexps(`(?m)^DISTRIB_DESCRIPTION='([^']+)'`),
		TimeoutMs: 1200,
	},
	"pfSense/OPNsense:pfSense": {
		Name:      "pfsense_uname",
		Command:   "uname -a",
		Guard:     guardLinuxShell,
		Expect:    compileRegexps(`FreeBSD`, `pfSense`),
		Scrape:    compileRegexps(`FreeBSD (\S+)`),
		TimeoutMs: 1200,
	},
}

func safeProbeKey(vendor, os string) string {
	return vendor + ":" + os
}

func getSafeProbe(vendor, os string) *SafeProbe {
	if probe, ok := safeProbes[safeProbeKey(vendor, os)]; ok {
		return probe
	}
	return nil
}
