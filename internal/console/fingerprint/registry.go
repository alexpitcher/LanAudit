package fingerprint

import (
	"regexp"
	"strings"
)

type regexPattern struct {
	Label string
	Regex *regexp.Regexp
}

// Signature describes identifying characteristics for a platform.
type Signature struct {
	Vendor        string
	OS            string
	PreLogin      []*regexPattern
	Login         []*regexPattern
	Prompt        []*regexPattern
	VersionScrape []*regexp.Regexp
	SafeProbe     *SafeProbe
	Weight        float64
}

var signatureRegistry []*Signature

func registerSignature(sig *Signature) {
	signatureRegistry = append(signatureRegistry, sig)
}

// GetCandidates scores signatures against rx/prompt text.
func GetCandidates(rx, prompt string) []Candidate {
	var candidates []Candidate

	for _, sig := range signatureRegistry {
		score := sig.Weight
		evidence := make([]string, 0, 4)
		matched := false

		for _, pat := range sig.PreLogin {
			if pat.Regex.MatchString(rx) {
				score += 0.5
				matched = true
				evidence = append(evidence, "prelogin: "+pat.Label)
				break
			}
		}

		for _, pat := range sig.Login {
			if pat.Regex.MatchString(rx) {
				score += 0.2
				matched = true
				evidence = append(evidence, "login: "+pat.Label)
				break
			}
		}

		for _, pat := range sig.Prompt {
			if pat.Regex.MatchString(prompt) {
				score += 0.35
				matched = true
				evidence = append(evidence, "prompt: "+pat.Label)
				break
			}
		}

		if !matched {
			continue
		}

		cand := Candidate{
			Vendor:        sig.Vendor,
			OS:            sig.OS,
			Prob:          clamp01(score),
			Evidence:      evidence,
			NextSafeProbe: sig.SafeProbe,
		}
		candidates = append(candidates, cand)
	}

	return candidates
}

func lookupSignature(vendor, os string) *Signature {
	for _, sig := range signatureRegistry {
		if sig.Vendor == vendor && sig.OS == os {
			return sig
		}
	}
	return nil
}

func scrapeModel(text string, cand Candidate) string {
	sig := lookupSignature(cand.Vendor, cand.OS)
	if sig == nil {
		return ""
	}
	for _, re := range sig.VersionScrape {
		if match := re.FindStringSubmatch(text); len(match) > 1 {
			return strings.TrimSpace(match[1])
		}
	}
	return ""
}
