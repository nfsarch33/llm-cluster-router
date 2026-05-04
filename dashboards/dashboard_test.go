package dashboards

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requiredMetrics is the canonical metric set the router exposes
// (see main.go). The dashboard must reference each so the
// out-of-the-box experience for an operator who imports the JSON
// is "every panel renders". Drift between the router's metric
// names and the dashboard surfaces here as a hard test failure.
var requiredMetrics = []string{
	"llm_router_request_duration_seconds",
	"llm_router_request_ttft_seconds",
	"llm_router_queue_depth",
	"llm_router_inflight_requests",
	"llm_router_node_healthy",
	"llm_router_requests_total",
	"llm_router_circuit_state",
}

// TestDashboardJSONIsValid asserts dashboards/llm-cluster-router.json
// parses, has a non-empty title, and exposes at least one panel
// per required metric.
func TestDashboardJSONIsValid(t *testing.T) {
	t.Parallel()

	path := filepath.Join("llm-cluster-router.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	var dashboard map[string]any
	if err := json.Unmarshal(data, &dashboard); err != nil {
		t.Fatalf("parse dashboard: %v", err)
	}

	title, _ := dashboard["title"].(string)
	if strings.TrimSpace(title) == "" {
		t.Fatal("dashboard title must be non-empty")
	}

	panels, ok := dashboard["panels"].([]any)
	if !ok || len(panels) == 0 {
		t.Fatal("dashboard must define at least one panel")
	}

	for _, panel := range panels {
		p, ok := panel.(map[string]any)
		if !ok {
			t.Fatal("each panel must be a JSON object")
		}
		pt, _ := p["title"].(string)
		if strings.TrimSpace(pt) == "" {
			t.Fatalf("panel %v has empty title", p["id"])
		}
		targets, ok := p["targets"].([]any)
		if !ok || len(targets) == 0 {
			t.Fatalf("panel %q has no targets", pt)
		}
		for _, target := range targets {
			tgt, ok := target.(map[string]any)
			if !ok {
				t.Fatalf("panel %q target is not an object", pt)
			}
			expr, _ := tgt["expr"].(string)
			if strings.TrimSpace(expr) == "" {
				t.Fatalf("panel %q has a target with empty expr", pt)
			}
		}
	}

	flat := string(data)
	for _, metric := range requiredMetrics {
		if !strings.Contains(flat, metric) {
			t.Fatalf("dashboard must reference metric %q at least once", metric)
		}
	}
}

// TestDashboardJSONHasDatasourceVariable asserts the dashboard
// declares a $datasource template variable so an operator can
// import the JSON into any Grafana org without editing each
// panel.
func TestDashboardJSONHasDatasourceVariable(t *testing.T) {
	t.Parallel()

	path := filepath.Join("llm-cluster-router.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	var dashboard map[string]any
	if err := json.Unmarshal(data, &dashboard); err != nil {
		t.Fatalf("parse dashboard: %v", err)
	}

	templating, _ := dashboard["templating"].(map[string]any)
	if templating == nil {
		t.Fatal("dashboard must declare templating block")
	}
	list, _ := templating["list"].([]any)
	if len(list) == 0 {
		t.Fatal("templating.list must define at least one variable")
	}

	found := false
	for _, v := range list {
		variable, ok := v.(map[string]any)
		if !ok {
			continue
		}
		name, _ := variable["name"].(string)
		ty, _ := variable["type"].(string)
		if name == "datasource" && ty == "datasource" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("dashboard must declare a $datasource templating variable so it can be imported into any Grafana org")
	}
}
