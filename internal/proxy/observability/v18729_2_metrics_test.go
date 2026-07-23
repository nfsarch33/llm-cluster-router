// Package observability / v18729_2_metrics_test.go
//
// v18729-2 contract tests for the model-labelled duration histogram
// + Grafana dashboard + Prometheus alert rules + Alertmanager
// notification routing.
//
// These tests are hermetic — they do NOT require a running
// Prometheus / Alertmanager / Grafana; they assert the on-disk
// artefacts are syntactically valid and the metric registration
// surface is complete.
package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

// TestRequestDurationByModel_Registered asserts the new histogram
// is registered with the production-isolated registry and that a
// sample can be observed + scraped.
func TestRequestDurationByModel_Registered(t *testing.T) {
	reg := prometheus.NewRegistry()
	if err := RegisterMetrics(reg); err != nil {
		t.Fatalf("RegisterMetrics: %v", err)
	}
	// A model-labelled sample must be observable without panic.
	ObserveRequestDurationByModel("aes-mtls", "MiniMax-M3", 0.123)
	ObserveRequestDurationByModel("socks5", "qwen3.7-plus", 0.456)
	// Empty model is a no-op (per ObserveRequestDurationByModel contract).
	ObserveRequestDurationByModel("tls-edge", "", 0.789)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "llm_cluster_router_request_duration_by_model_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if _, ok := labels["model"]; ok {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("llm_cluster_router_request_duration_seconds{model=...} series not found in registry output")
	}
}

// TestGrafanaHelixChannelDashboard_ValidJSON asserts the dashboard
// JSON is parseable and contains the v18729-2 panels.
func TestGrafanaHelixChannelDashboard_ValidJSON(t *testing.T) {
	path := repoFile(t, "observability/grafana/helixchannel.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var d map[string]interface{}
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("Unmarshal dashboard JSON: %v", err)
	}
	if d["title"] == nil {
		t.Errorf("dashboard missing title")
	}
	panels, ok := d["panels"].([]interface{})
	if !ok {
		t.Fatalf("dashboard panels is not an array")
	}
	if len(panels) < 5 {
		t.Errorf("dashboard has %d panels; expected ≥ 5 (connections, TTFB p95, decrypt-failed, 5xx, stats)", len(panels))
	}
	titles := map[string]bool{}
	for _, p := range panels {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if t, ok := pm["title"].(string); ok {
			titles[t] = true
		}
	}
	for _, want := range []string{
		"Connections /s by listener × outcome",
		"TTFB p95 by listener × model",
		"Decrypt-failed rate by listener",
		"5xx-rate / failure outcomes /s",
	} {
		if !titles[want] {
			t.Errorf("dashboard missing panel %q", want)
		}
	}
}

// TestPrometheusAlertsHelixChannel_ValidYAML asserts the v18729-2
// alert rules parse and contain the four SLOs.
func TestPrometheusAlertsHelixChannel_ValidYAML(t *testing.T) {
	path := repoFile(t, "observability/alerts/helixchannel.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert string `yaml:"alert"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Unmarshal alert rules YAML: %v", err)
	}
	if len(doc.Groups) == 0 {
		t.Fatalf("alert rules YAML has zero groups")
	}
	alerts := map[string]bool{}
	for _, g := range doc.Groups {
		for _, r := range g.Rules {
			alerts[r.Alert] = true
		}
	}
	for _, want := range []string{
		"HelixChannelTTFBHigh",
		"HelixChannel5xxRateHigh",
		"HelixChannelDecryptFailedRateHigh",
		"HelixChannelConnectionErrors",
	} {
		if !alerts[want] {
			t.Errorf("alert rules YAML missing %s", want)
		}
	}
}

// TestAlertmanagerHelixChannel_ValidYAML asserts the Alertmanager
// routing config parses and includes Slack + email receivers.
func TestAlertmanagerHelixChannel_ValidYAML(t *testing.T) {
	path := repoFile(t, "observability/alertmanager/helixchannel.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	var doc struct {
		Receivers []struct {
			Name string `yaml:"name"`
		} `yaml:"receivers"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Unmarshal Alertmanager YAML: %v", err)
	}
	names := map[string]bool{}
	for _, r := range doc.Receivers {
		names[r.Name] = true
	}
	for _, want := range []string{"helixchannel-page", "helixchannel-warn"} {
		if !names[want] {
			t.Errorf("Alertmanager config missing receiver %q", want)
		}
	}
	// Assert the file does NOT contain SMTP hostnames (per the
	// email-vendor-rotation rule: API only).
	bs := string(data)
	if strings.Contains(bs, "smtp.sendgrid.net") ||
		strings.Contains(bs, "smtp.mailgun.org") ||
		strings.Contains(bs, "smtp-relay.brevo.com") ||
		strings.Contains(bs, "smtp2go.com") {
		t.Errorf("Alertmanager config references an SMTP relay; API-only per email-vendor-rotation rule")
	}
}

// repoFile resolves a path relative to the repo root. The
// test runner cwd is the package directory; we walk upward until
// we find go.mod.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, rel)
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("could not find repo root from %s", cwd)
	return ""
}
