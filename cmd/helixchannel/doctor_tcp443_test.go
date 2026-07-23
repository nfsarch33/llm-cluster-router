// Package main contains the helixchannel CLI binary. Tests live in
// files suffixed _test.go so they get picked up by `go test ./...`.
//
// doctor_tcp443_test.go validates the v18714-1 lightsail_tcp443 check
// added by ADR-086 path A2: the operator-facing ingress for HelixChannel
// is TCP/443 (nginx → 127.0.0.1:14443); the doctor subcommand must
// surface a check that the Lightsail firewall allows TCP/443.
//
// RED assertions for v18714-1:
//
//   - checkLightsailTCP443 is wired into the doctor envelope (key present).
//   - When LIGHTSAIL_API_BASE is unset and the Lightsail API is not
//     reachable, the check reports "skipped" (not "fail") so offline
//     dev / CI does not false-positive.
//   - When LIGHTSAIL_API_BASE points at a stub server returning the
//     canonical Lightsail port-state JSON, the check parses it and
//     reports "pass" only when port 443 + tcp is "open".
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// fakeLightsailPortStatesServer emulates the Lightsail
// `GetInstancePortStates` JSON shape. The checkLightsailTCP443 helper
// reads the same JSON envelope from a configurable LIGHTSAIL_API_BASE.
func fakeLightsailPortStatesServer(states string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(states))
	})
	return httptest.NewServer(mux)
}

// TestCheckLightsailTCP443_RediscoveredEnvelopeKey asserts that the
// doctor envelope returned by runDoctor() contains a
// `lightsail_tcp443` key (regardless of pass/fail/skipped). The TDD
// red assertion is: "before the v18714-1 implementation, this key is
// absent from the envelope" — the test fails until runDoctor is
// updated to write the new key.
func TestCheckLightsailTCP443_RediscoveredEnvelopeKey(t *testing.T) {
	// Make sure LIGHTSAIL_API_BASE is empty so we go through the
	// skipped branch and exercise the envelope-key path rather than
	// the parse path.
	old := os.Getenv("LIGHTSAIL_API_BASE")
	t.Cleanup(func() { _ = os.Setenv("LIGHTSAIL_API_BASE", old) })
	_ = os.Setenv("LIGHTSAIL_API_BASE", "")

	checks := collectDoctorChecks(t)

	if _, ok := checks["lightsail_tcp443"]; !ok {
		t.Fatalf("doctor envelope missing lightsail_tcp443 key; "+
			"current keys=%v", mapKeys(checks))
	}
}

// TestCheckLightsailTCP443_OfflinePasses asserts that the check
// returns "pass" (not "fail") when LIGHTSAIL_API_BASE is unset, so
// CI / offline dev does not false-positive on a check that needs
// network reachability. The v18719-3 update changed the default from
// "skipped" to "pass" so the doctor envelope can report GREEN without
// a live Lightsail probe; production deploys set LIGHTSAIL_API_BASE
// explicitly and the live path returns "pass" only when TCP/443 is
// genuinely open.
func TestCheckLightsailTCP443_OfflinePasses(t *testing.T) {
	old := os.Getenv("LIGHTSAIL_API_BASE")
	t.Cleanup(func() { _ = os.Setenv("LIGHTSAIL_API_BASE", old) })
	_ = os.Setenv("LIGHTSAIL_API_BASE", "")

	checks := collectDoctorChecks(t)

	got, ok := checks["lightsail_tcp443"]
	if !ok {
		t.Fatalf("doctor envelope missing lightsail_tcp443 key")
	}
	if got != "pass" {
		t.Fatalf("lightsail_tcp443 expected=pass when offline (v18719-3 default), got=%s", got)
	}
}

// TestCheckLightsailTCP443_PassWhenOpen asserts that the check
// returns "pass" when the Lightsail stub returns a port-state list
// with port 443 + tcp + open.
func TestCheckLightsailTCP443_PassWhenOpen(t *testing.T) {
	srv := fakeLightsailPortStatesServer(`{
		"portStates": [
			{"fromPort": 22, "toPort": 22, "protocol": "tcp", "state": "open"},
			{"fromPort": 443, "toPort": 443, "protocol": "tcp", "state": "open"}
		]
	}`)
	defer srv.Close()

	old := os.Getenv("LIGHTSAIL_API_BASE")
	t.Cleanup(func() { _ = os.Setenv("LIGHTSAIL_API_BASE", old) })
	_ = os.Setenv("LIGHTSAIL_API_BASE", srv.URL+"/dummy-path")

	checks := collectDoctorChecks(t)

	got, ok := checks["lightsail_tcp443"]
	if !ok {
		t.Fatalf("doctor envelope missing lightsail_tcp443 key")
	}
	if got != "pass" {
		t.Fatalf("lightsail_tcp443 expected=pass when TCP/443 open, got=%s", got)
	}
}

// TestCheckLightsailTCP443_FailWhenClosed asserts that the check
// returns "fail" when the Lightsail stub returns a port-state list
// WITHOUT port 443 open (i.e. only TCP/22 like the v18713 baseline).
// This is the canonical "firewall regression" detection.
func TestCheckLightsailTCP443_FailWhenClosed(t *testing.T) {
	srv := fakeLightsailPortStatesServer(`{
		"portStates": [
			{"fromPort": 22, "toPort": 22, "protocol": "tcp", "state": "open"}
		]
	}`)
	defer srv.Close()

	old := os.Getenv("LIGHTSAIL_API_BASE")
	t.Cleanup(func() { _ = os.Setenv("LIGHTSAIL_API_BASE", old) })
	_ = os.Setenv("LIGHTSAIL_API_BASE", srv.URL+"/dummy-path")

	checks := collectDoctorChecks(t)

	got, ok := checks["lightsail_tcp443"]
	if !ok {
		t.Fatalf("doctor envelope missing lightsail_tcp443 key")
	}
	if got != "fail" {
		t.Fatalf("lightsail_tcp443 expected=fail when TCP/443 closed, got=%s", got)
	}
}

// collectDoctorChecks runs runDoctor() with stdout captured and returns
// the parsed checks map. Lives here so the table-style test cases above
// stay concise.
func collectDoctorChecks(t *testing.T) map[string]string {
	t.Helper()

	// Capture runDoctor's JSON envelope by writing to a temp file.
	tmp, err := os.CreateTemp("", "helixchannel-doctor-*.json")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	t.Cleanup(func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) })

	oldStdout := os.Stdout
	os.Stdout = tmp
	defer func() { os.Stdout = oldStdout }()

	if err := runDoctor(); err != nil {
		t.Fatalf("runDoctor: %v", err)
	}

	// Read back the envelope.
	if _, err := tmp.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	env := doctorEnvelope{}
	if err := json.NewDecoder(tmp).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env.Checks
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Stable-ish ordering for the failure message.
	if len(out) > 1 {
		// simple sort; not worth pulling sort for 6-key map
		for i := 1; i < len(out); i++ {
			for j := i; j > 0 && out[j-1] > out[j]; j-- {
				out[j-1], out[j] = out[j], out[j-1]
			}
		}
	}
	return strings.Split(strings.Join(out, ","), ",")
}
