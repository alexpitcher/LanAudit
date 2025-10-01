package fingerprint

import "regexp"

type patternSpec struct {
	label string
	regex string
}

func makePatternSlice(specs []patternSpec) []*regexPattern {
	out := make([]*regexPattern, 0, len(specs))
	for _, spec := range specs {
		out = append(out, &regexPattern{
			Label: spec.label,
			Regex: regexp.MustCompile(spec.regex),
		})
	}
	return out
}

func makeVersionRegex(ps ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(ps))
	for _, p := range ps {
		if p == "" {
			continue
		}
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

func init() {
	registerSignature(&Signature{
		Vendor:   "Cisco",
		OS:       "IOS",
		Weight:   0.05,
		PreLogin: makePatternSlice([]patternSpec{{"User Access Verification", `User Access Verification`}, {"Cisco IOS banner", `Cisco IOS`}}),
		Login:    makePatternSlice([]patternSpec{{"Username prompt", `(?i)^username:`}, {"Password prompt", `(?i)^password:`}}),
		Prompt:   makePatternSlice([]patternSpec{{"Cisco IOS prompt", `(?m)^([A-Za-z0-9._-]+)(\((config[^\)]*)\))?[#>] ?$`}}),
		VersionScrape: makeVersionRegex(
			`(?m)^[Cc]isco (Catalyst|Switch|Router)\s+([A-Z0-9-]+)`,
			`(?m)^Model number\s+:\s+(\S+)`,
		),
		SafeProbe: getSafeProbe("Cisco", "IOS"),
	})

	registerSignature(&Signature{
		Vendor:   "Cisco",
		OS:       "IOS-XE",
		Weight:   0.05,
		PreLogin: makePatternSlice([]patternSpec{{"Cisco IOS-XE", `IOS[- ]XE`}}),
		Login:    makePatternSlice([]patternSpec{{"Username prompt", `(?i)^username:`}}),
		Prompt:   makePatternSlice([]patternSpec{{"Cisco IOS prompt", `(?m)^([A-Za-z0-9._-]+)(\((config[^\)]*)\))?[#>] ?$`}}),
		VersionScrape: makeVersionRegex(
			`(?m)^Cisco (\S+) Software`,
			`(?m)^cisco (\S+) \(`,
		),
		SafeProbe: getSafeProbe("Cisco", "IOS-XE"),
	})

	registerSignature(&Signature{
		Vendor:        "Cisco",
		OS:            "NX-OS",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"Cisco Nexus", `Cisco Nexus Operating System`}}),
		Prompt:        makePatternSlice([]patternSpec{{"NX-OS prompt", `(?m)^(Nexus|switch)[#>] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^\s*(cisco Nexus .*?)$`, `(?m)^Hardware\s+:\s+(.*)`),
		SafeProbe:     getSafeProbe("Cisco", "NX-OS"),
	})

	registerSignature(&Signature{
		Vendor:        "Cisco",
		OS:            "IOS-XR",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"IOS XR", `IOS XR`}}),
		Prompt:        makePatternSlice([]patternSpec{{"IOS XR prompt", `(?m)^RP/\d+/\S+:\S+# ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^cisco IOS XR Software, Version ([\w.\-]+)`),
		SafeProbe:     getSafeProbe("Cisco", "IOS-XR"),
	})

	registerSignature(&Signature{
		Vendor:        "Cisco",
		OS:            "ASA",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"Cisco ASA", `Cisco Adaptive Security Appliance`}}),
		Prompt:        makePatternSlice([]patternSpec{{"ASA prompt", `(?m)^ciscoasa(?:\([^\)]*\))?[#>] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Hardware\s+:\s+(.*)`),
		SafeProbe:     getSafeProbe("Cisco", "ASA"),
	})

	registerSignature(&Signature{
		Vendor:        "Aruba",
		OS:            "AOS-CX",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"ArubaOS-CX", `ArubaOS-CX`}}),
		Prompt:        makePatternSlice([]patternSpec{{"Aruba CX prompt", `(?mi)^(mgr|admin|[A-Za-z0-9._-]+)# ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Platform :\s+(.*)`),
		SafeProbe:     getSafeProbe("Aruba", "AOS-CX"),
	})

	registerSignature(&Signature{
		Vendor:        "Aruba",
		OS:            "AOS-S",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"ArubaOS-S", `Aruba 2930F|ProCurve|ArubaOS-S`}}),
		Prompt:        makePatternSlice([]patternSpec{{"Aruba AOS-S prompt", `(?m)^(HP|Aruba|ProCurve)[\w\-]*[>#] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Image stamp: (.*)`, `(?m)^ROM Version : (.*)`),
		SafeProbe:     getSafeProbe("Aruba", "AOS-S"),
	})

	registerSignature(&Signature{
		Vendor:        "Juniper",
		OS:            "JUNOS",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"JUNOS", `JUNOS`}, {"Amnesiac", `Amnesiac`}}),
		Login:         makePatternSlice([]patternSpec{{"login:", `(?i)^login:`}}),
		Prompt:        makePatternSlice([]patternSpec{{"Junos prompt", `(?m)^[\w\-]+@[\w\-.]+[>#] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Model:\s+(\S+)`),
		SafeProbe:     getSafeProbe("Juniper", "JUNOS"),
	})

	registerSignature(&Signature{
		Vendor:        "MikroTik",
		OS:            "RouterOS",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"RouterOS", `MikroTik RouterOS`}}),
		Prompt:        makePatternSlice([]patternSpec{{"MikroTik prompt", `(?m)^\[[^\]]+\]\s?> ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^\s*board-name:\s+(.*)`),
		SafeProbe:     getSafeProbe("MikroTik", "RouterOS"),
	})

	registerSignature(&Signature{
		Vendor:        "Ubiquiti",
		OS:            "EdgeOS",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"EdgeOS", `Welcome to EdgeOS`}}),
		Prompt:        makePatternSlice([]patternSpec{{"EdgeOS prompt", `(?m)^[\w\-]+@[\w\-.]+(:~)?[$#] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Linux (\S+)`),
		SafeProbe:     getSafeProbe("Ubiquiti", "EdgeOS"),
	})

	registerSignature(&Signature{
		Vendor:        "Fortinet",
		OS:            "FortiOS",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"FortiGate", `FortiGate`}}),
		Login:         makePatternSlice([]patternSpec{{"FortiGate login", `FortiGate-\w+ login:`}}),
		Prompt:        makePatternSlice([]patternSpec{{"FortiGate prompt", `(?m)^FGT\w*\s?[#>] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Version:\s+(.*)`),
		SafeProbe:     getSafeProbe("Fortinet", "FortiOS"),
	})

	registerSignature(&Signature{
		Vendor:        "PaloAlto",
		OS:            "PAN-OS",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"PA banner", `PA-\d+`}}),
		Prompt:        makePatternSlice([]patternSpec{{"PAN-OS prompt", `(?m)^[\w\-]+@PA-\w+[>#] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^model:\s+(\S+)`),
		SafeProbe:     getSafeProbe("PaloAlto", "PAN-OS"),
	})

	registerSignature(&Signature{
		Vendor:        "Huawei",
		OS:            "VRP",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"Huawei VRP", `HUAWEI`}}),
		Prompt:        makePatternSlice([]patternSpec{{"VRP prompt", `(?m)^(<[Hh][PpEe]?[^>]*>|\[[Hh].*?\])$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Product Version: (.*)`, `(?m)^Huawei Versatile Routing Platform Software \(VRP\) (.*)`),
		SafeProbe:     getSafeProbe("Huawei", "VRP"),
	})

	registerSignature(&Signature{
		Vendor:        "HPE",
		OS:            "Comware",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"Comware", `Comware`}}),
		Prompt:        makePatternSlice([]patternSpec{{"Comware prompt", `(?m)^((<|\[)HPE?.*?(>|\]))$`}}),
		VersionScrape: makeVersionRegex(`(?m)^System Name: (.*)`, `(?m)^HP Comware Platform Software, Version (.*)`),
		SafeProbe:     getSafeProbe("HPE", "Comware"),
	})

	registerSignature(&Signature{
		Vendor:        "Dell",
		OS:            "OS10",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"Dell OS10", `Dell EMC Networking OS10`}}),
		Prompt:        makePatternSlice([]patternSpec{{"Dell prompt", `(?m)^Dell\w*[#>] ?$`}, {"Generic shell", `(?m)^.*[>#] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Product:\s+(.*)`),
		SafeProbe:     getSafeProbe("Dell", "OS10"),
	})

	registerSignature(&Signature{
		Vendor:        "Brocade/Extreme",
		OS:            "FastIron",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"FastIron", `FastIron`}}),
		Prompt:        makePatternSlice([]patternSpec{{"ICX prompt", `(?m)^(ICX|BR-CD|FastIron).*?[#>] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^System Model:\s+(.*)`),
		SafeProbe:     getSafeProbe("Brocade/Extreme", "FastIron"),
	})

	registerSignature(&Signature{
		Vendor:        "VyOS",
		OS:            "VyOS",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"VyOS login", `vyos login:`}}),
		Prompt:        makePatternSlice([]patternSpec{{"VyOS prompt", `(?m)^vyos@.*[$#] ?$`}}),
		VersionScrape: makeVersionRegex(`(?m)^Version: (.*)`),
		SafeProbe:     getSafeProbe("VyOS", "VyOS"),
	})

	registerSignature(&Signature{
		Vendor:        "OpenWrt",
		OS:            "OpenWrt",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"OpenWrt", `OpenWrt`}}),
		Prompt:        makePatternSlice([]patternSpec{{"OpenWrt prompt", `(?m)^root@OpenWrt:~#$`}}),
		VersionScrape: makeVersionRegex(`(?m)^DISTRIB_DESCRIPTION='([^']+)'`),
		SafeProbe:     getSafeProbe("OpenWrt", "OpenWrt"),
	})

	registerSignature(&Signature{
		Vendor:        "pfSense/OPNsense",
		OS:            "pfSense",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"pfSense", `pfSense`}}),
		Prompt:        makePatternSlice([]patternSpec{{"pfSense prompt", `(?m)^root@pfSense:~ #$`}}),
		VersionScrape: makeVersionRegex(`(?m)^FreeBSD (\S+)`),
		SafeProbe:     getSafeProbe("pfSense/OPNsense", "pfSense"),
	})

	registerSignature(&Signature{
		Vendor:        "Bootloader",
		OS:            "U-Boot",
		Weight:        0.1,
		PreLogin:      makePatternSlice([]patternSpec{{"U-Boot", `\bU-Boot\b`}}),
		Prompt:        makePatternSlice([]patternSpec{{"U-Boot prompt", `(?m)^=> ?$`}}),
		VersionScrape: makeVersionRegex(`U-Boot\s+(\S+)`),
	})

	registerSignature(&Signature{
		Vendor:   "Bootloader",
		OS:       "ROMMON",
		Weight:   0.1,
		PreLogin: makePatternSlice([]patternSpec{{"ROMMON", `ROMMON`}, {"System Bootstrap", `System Bootstrap`}}),
		Prompt:   makePatternSlice([]patternSpec{{"rommon prompt", `(?m)^rommon \d+ >$`}}),
	})

	registerSignature(&Signature{
		Vendor:   "Bootloader",
		OS:       "GRUB",
		Weight:   0.1,
		PreLogin: makePatternSlice([]patternSpec{{"GNU GRUB", `GNU GRUB`}}),
	})

	registerSignature(&Signature{
		Vendor:        "Linux/BusyBox",
		OS:            "Linux",
		Weight:        0.05,
		PreLogin:      makePatternSlice([]patternSpec{{"BusyBox", `BusyBox`}, {"Linux", `Linux version`}}),
		Prompt:        makePatternSlice([]patternSpec{{"Shell prompt", `(?m)^.*[$#] ?$`}}),
		VersionScrape: makeVersionRegex(`Linux (\S+)`),
		SafeProbe:     getSafeProbe("Linux/BusyBox", "Linux"),
	})
}
