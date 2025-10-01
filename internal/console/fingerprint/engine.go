package fingerprint

import (
	"sort"
	"strings"
	"time"

	"github.com/alexpitcher/LanAudit/internal/logging"
)

// Stage represents the lifecycle phase of a console interaction.
type Stage string

const (
	StagePreLogin Stage = "prelogin"
	StageLogin    Stage = "login"
	StagePrompt   Stage = "prompt"
	StageBoot     Stage = "bootloader"
)

// Candidate describes a potential fingerprint match.
type Candidate struct {
	Vendor        string
	OS            string
	Prob          float64
	Evidence      []string
	NextSafeProbe *SafeProbe
	stage         Stage
	Prompt        string
}

// Result captures the final fingerprint decision.
type Result struct {
	Vendor     string
	OS         string
	Model      string
	Prompt     string
	Stage      Stage
	Baud       int
	Confidence float64
	Evidence   []string
}

// WriterReader is implemented by console sessions for safe probes.
type WriterReader interface {
	Write([]byte) (int, error)
	ReadUntil(timeout time.Duration, terminators ...[]byte) (string, error)
}

// Analyze processes RX text and returns the current Stage plus ranked candidates.
func Analyze(rx string, lastPrompt string) (Stage, []Candidate) {
	normalized := Normalize(rx)
	logging.Debugf("fingerprint.Analyze len(rx)=%d lastPrompt=%q", len(rx), lastPrompt)

	promptLine := strings.TrimSpace(lastPrompt)
	if promptLine == "" {
		promptLine = ExtractLastPromptLine(normalized)
	}

	stage := DetectStage(normalized, promptLine)

	candidates := GetCandidates(normalized, promptLine)
	for i := range candidates {
		candidates[i].stage = stage
		candidates[i].Prompt = promptLine
		candidates[i].Evidence = dedupeStrings(candidates[i].Evidence)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Prob == candidates[j].Prob {
			return candidates[i].Vendor < candidates[j].Vendor
		}
		return candidates[i].Prob > candidates[j].Prob
	})
	logging.Debugf("Analyze stage=%s candidates=%d", stage, len(candidates))

	return stage, candidates
}

// MaybeProbe executes a single safe probe if the candidate qualifies.
func MaybeProbe(sess WriterReader, cand Candidate, timeout time.Duration) (string, *Candidate, error) {
	if sess == nil || cand.NextSafeProbe == nil {
		return "", nil, nil
	}

	if cand.stage != StagePrompt {
		return "", nil, nil
	}

	if cand.Prob < 0.55 {
		return "", nil, nil
	}

	probe := cand.NextSafeProbe
	if probe == nil {
		return "", nil, nil
	}
	logging.Infof("MaybeProbe candidate vendor=%s os=%s prob=%.2f stage=%s", cand.Vendor, cand.OS, cand.Prob, cand.stage)

	if probe.Guard != nil && !probe.Guard.MatchString(cand.Prompt) {
		return "", nil, nil
	}

	cmd := probe.Command
	if !strings.HasSuffix(cmd, "\n") {
		cmd += "\r\n"
	}

	if _, err := sess.Write([]byte(cmd)); err != nil {
		logging.Errorf("probe write failed: %v", err)
		return "", nil, err
	}

	t := timeout
	if t <= 0 {
		if probe.TimeoutMs > 0 {
			t = time.Duration(probe.TimeoutMs) * time.Millisecond
		} else {
			t = 1100 * time.Millisecond
		}
	}

	terminators := [][]byte{[]byte("#"), []byte(">"), []byte("$"), []byte("\n")}
	output, err := sess.ReadUntil(t, terminators...)
	if err != nil {
		logging.Warnf("probe read error: %v", err)
		return output, nil, err
	}

	updated := cand
	scoreBoost := probe.Score(output)
	if scoreBoost > 0 {
		updated.Prob = clamp01(updated.Prob + scoreBoost)
		updated.Evidence = append(updated.Evidence, probe.Name+" probe expect matched")
		logging.Debugf("probe expect matched for %s", probe.Name)
	} else {
		updated.Evidence = append(updated.Evidence, probe.Name+" probe output recorded")
	}

	if model := probe.ScrapeModel(output); model != "" {
		updated.Evidence = append(updated.Evidence, "model: "+model)
		logging.Debugf("probe scraped model %s", model)
	}

	logging.Infof("probe completed for %s/%s", cand.Vendor, cand.OS)
	return output, &updated, nil
}

// Finalize derives the final fingerprint result using all context.
func Finalize(stage Stage, cands []Candidate, rx, prompt, probeOut string) Result {
	res := Result{Stage: stage, Prompt: strings.TrimSpace(prompt)}

	if len(cands) == 0 {
		res.Vendor = "Unknown"
		res.OS = "Unknown"
		res.Evidence = shortlistEvidence([]string{"no candidates"})
		logging.Warnf("Finalize: no candidates for provided input")
		return res
	}

	top := cands[0]
	res.Vendor = top.Vendor
	res.OS = top.OS
	res.Confidence = clamp01(top.Prob)
	res.Evidence = shortlistEvidence(top.Evidence)

	if model := scrapeModel(rx, top); model != "" {
		res.Model = model
	}
	if res.Model == "" && probeOut != "" {
		res.Model = scrapeModel(probeOut, top)
	}

	if probeOut != "" {
		res.Evidence = shortlistEvidence(append(res.Evidence, "probe output captured"))
	}
	logging.Infof("Finalize result vendor=%s os=%s model=%s confidence=%.2f", res.Vendor, res.OS, res.Model, res.Confidence)

	return res
}

// EvidenceString returns newline-separated evidence for guard checks.
func (c Candidate) EvidenceString() string {
	if len(c.Evidence) == 0 {
		return ""
	}
	return strings.Join(c.Evidence, "\n")
}

func shortlistEvidence(evs []string) []string {
	deduped := dedupeStrings(evs)
	if len(deduped) > 3 {
		return deduped[:3]
	}
	return deduped
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}
