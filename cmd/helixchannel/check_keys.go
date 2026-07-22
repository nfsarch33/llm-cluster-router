// check_keys.go implements the v18716.3 `helixchannel check-keys`
// subcommand. It probes each 1Password key UUID declared in the
// config (or the default key list) by calling `op read
// op://<vault>/<item>/<field>` and reports a per-key verdict.
//
// Operator workflow:
//
//	helixchannel check-keys                          # default: minimax
//	helixchannel check-keys --config /etc/helix.yaml # all keys in config
//	helixchannel check-keys --keys minimax,grafana    # subset by name
//
// Exit codes (verdictError convention):
//
//	0  all probed keys PASS (op returns a non-empty secret)
//	1  any probed key FAIL (op exits non-zero)
//	2  any probed key SKIP (op not installed, or key list empty)
//
// Anti-shell-leak: secret values are NEVER included in the envelope.
// Only the byte length is reported so the operator can detect a
// truncated / stale secret without printing it. See
// guardrails/1password-usage.mdc and no-shell-leak.mdc.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// defaultCheckKeys is the canonical v18716 key inventory. Mirrors
// docs/kilo-code-setup.md § Prerequisites. Operators can extend
// this set via --config; the slice here is the always-probed set
// when --config is not provided.
var defaultCheckKeys = []ConfigKeyRef{
	{
		Name:  "minimax",
		Vault: "HelixonSafe",
		Item:  "ripotpfq43jzlreor4zo2ay734",
		Field: "tagc4supdfgjj3rujdpb67ygm",
	},
}

// checkKeyResult is one row in the JSON envelope. ByteLength
// is the count of bytes returned by `op read` (NOT the value
// itself); the operator can sanity-check the secret length
// without ever seeing the value.
type checkKeyResult struct {
	Name       string `json:"name"`
	Vault      string `json:"vault"`
	Item       string `json:"item"`
	Field      string `json:"field"`
	Status     string `json:"status"` // pass | fail | skip
	ByteLength int    `json:"byte_length,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	ErrorClass string `json:"error_class,omitempty"` // op_missing | not_found | empty | op_nonzero | incomplete_ref | tmp_*
	Hint       string `json:"hint,omitempty"`
}

// checkKeysEnvelope is the JSON envelope emitted by the
// check-keys subcommand. Verdict is one of pass|fail|skip and
// mirrors the exit code so callers do not have to inspect
// strings.
type checkKeysEnvelope struct {
	Verdict  string           `json:"verdict"`
	Keys     []checkKeyResult `json:"keys"`
	ProbedAt string           `json:"probed_at"`
}

// runCheckKeys probes each key. --keys is a comma-separated
// subset of the configured key names. When --config is empty
// we probe the canonical defaultCheckKeys set. Empty result
// after filtering is a SKIP verdict with exit 2.
func runCheckKeys(args []string) error {
	fs := flag.NewFlagSet("check-keys", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to YAML config (uses cfg.Keys if non-empty)")
	subset := fs.String("keys", "", "comma-separated subset of key names to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("--config: %w", err)
	}

	// Build the working set: config keys + canonical defaults, then
	// filter to --keys subset if the operator passed one.
	working := append([]ConfigKeyRef{}, defaultCheckKeys...)
	working = append(working, cfg.Keys...)
	working = dedupeKeys(working)

	if *subset != "" {
		working = filterKeysByName(working, *subset)
	}

	envelope := checkKeysEnvelope{
		Keys:     make([]checkKeyResult, 0, len(working)),
		ProbedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}

	overallVerdict := "pass"
	for _, k := range working {
		res := probeOnePasswordKey(k)
		envelope.Keys = append(envelope.Keys, res)
		switch res.Status {
		case "fail":
			if overallVerdict != "skip" {
				overallVerdict = "fail"
			}
		case "skip":
			if overallVerdict == "pass" {
				overallVerdict = "skip"
			}
		}
	}

	if len(working) == 0 {
		envelope.Verdict = "skip"
		_ = json.NewEncoder(os.Stdout).Encode(envelope)
		return verdictSkipErr
	}

	envelope.Verdict = overallVerdict
	if err := json.NewEncoder(os.Stdout).Encode(envelope); err != nil {
		return err
	}

	switch overallVerdict {
	case "fail":
		return verdictFailErr
	case "skip":
		return verdictSkipErr
	default:
		return nil
	}
}

// probeOnePasswordKey shells out to `op read
// op://<vault>/<item>/<field>` and classifies the result. The
// op invocation uses `-o <tmpfile>` so the value goes to a
// tmp file (never argv) and we read the file back. The file is
// deleted in a defer block.
//
// Anti-patterns avoided:
//   - Never pipe `op read ... | ...` (argv leak).
//   - Never echo the value back to stdout.
//   - Never include the secret bytes in the envelope.
func probeOnePasswordKey(k ConfigKeyRef) checkKeyResult {
	res := checkKeyResult{
		Name:   k.Name,
		Vault:  k.Vault,
		Item:   k.Item,
		Field:  k.Field,
		Status: "skip",
	}
	start := time.Now()
	defer func() { res.DurationMs = time.Since(start).Milliseconds() }()

	if k.Vault == "" || k.Item == "" || k.Field == "" {
		res.ErrorClass = "incomplete_ref"
		res.Hint = "config entry is missing vault/item/field; fix the YAML and re-run"
		res.Status = "fail"
		return res
	}
	if _, err := exec.LookPath("op"); err != nil {
		res.ErrorClass = "op_missing"
		res.Hint = "install the 1Password CLI (`brew install 1password-cli` or apt) and re-auth"
		res.Status = "skip"
		return res
	}

	// Resolve to a tmp file inside the OS tmp dir. Use a name
	// prefixed with `helixchannel-op-*` so cleanup is greppable.
	tmp, err := os.CreateTemp("", "helixchannel-op-*")
	if err != nil {
		res.ErrorClass = "tmp_create"
		res.Hint = err.Error()
		res.Status = "fail"
		return res
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ref := fmt.Sprintf("op://%s/%s/%s", k.Vault, k.Item, k.Field)
	cmd := exec.CommandContext(ctx, "op", "read", ref, "-o", tmpPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		outStr := strings.TrimSpace(string(out))
		switch {
		case strings.Contains(outStr, "isn't an item"):
			res.ErrorClass = "not_found"
			res.Hint = "1Password could not find the item/field; rotate the UUID pair and re-run"
		case strings.Contains(outStr, "not signed in"):
			res.ErrorClass = "op_unauth"
			res.Hint = "op is not signed in; run `op signin` and re-run"
		default:
			res.ErrorClass = "op_nonzero"
			res.Hint = outStr
		}
		res.Status = "fail"
		return res
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		res.ErrorClass = "tmp_read"
		res.Hint = err.Error()
		res.Status = "fail"
		return res
	}
	res.ByteLength = len(data)
	if res.ByteLength == 0 {
		res.ErrorClass = "empty"
		res.Hint = "op returned an empty secret; the item field may be unset or stale"
		res.Status = "fail"
		return res
	}
	res.Status = "pass"
	return res
}

// dedupeKeys preserves first occurrence order so the envelope
// matches the order the operator sees in the YAML file. The
// comparison is on (vault,item,field); multiple names pointing
// at the same secret are deduped to a single probe.
func dedupeKeys(in []ConfigKeyRef) []ConfigKeyRef {
	seen := map[string]bool{}
	out := make([]ConfigKeyRef, 0, len(in))
	for _, k := range in {
		key := strings.Join([]string{k.Vault, k.Item, k.Field}, "|")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, k)
	}
	return out
}

// filterKeysByName narrows the working set to the named subset.
// Empty subset returns the input unchanged. Unknown names are
// silently skipped (the operator gets a SHORTER envelope, not
// a fail).
func filterKeysByName(in []ConfigKeyRef, subset string) []ConfigKeyRef {
	if subset == "" {
		return in
	}
	wanted := map[string]bool{}
	for _, n := range strings.Split(subset, ",") {
		if n = strings.TrimSpace(n); n != "" {
			wanted[n] = true
		}
	}
	out := make([]ConfigKeyRef, 0, len(in))
	for _, k := range in {
		if wanted[k.Name] {
			out = append(out, k)
		}
	}
	return out
}

// verdictSkipErr / verdictFailErr mirror the kiloVerify* sentinels
// so `fail()` in main.go maps both subcommands to the same exit
// codes (1=fail, 2=skip). They are concrete *kiloVerifyVerdictError
// values; the typed-error check in fail() recognises them.
var (
	verdictSkipErr = &kiloVerifyVerdictError{code: 2, label: "skip"}
	verdictFailErr = &kiloVerifyVerdictError{code: 1, label: "fail"}
)
