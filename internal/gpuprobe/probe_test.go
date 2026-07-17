package gpuprobe

import (
	"context"
	"strings"
	"testing"
)

func TestParseGPUCSV_HappyPath(t *testing.T) {
	raw := `0, GPU-aaaa, 0000:01:00.0, NVIDIA GeForce RTX 3090, 24576 MiB, 4096 MiB, 73 %, 71
1, GPU-bbbb, 0000:02:00.0, NVIDIA GeForce RTX 2070, 8192 MiB, 1024 MiB, 25 %, 45`
	gpus, err := ParseGPUCSV(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 2 {
		t.Fatalf("expected 2 GPUs, got %d", len(gpus))
	}
	g0 := gpus[0]
	if g0.Index != 0 || g0.UUID != "GPU-aaaa" || g0.PCIBusID != "0000:01:00.0" ||
		g0.Name != "NVIDIA GeForce RTX 3090" || g0.MemoryTotalMiB != 24576 ||
		g0.MemoryUsedMiB != 4096 || g0.UtilizationGPU != 73 || g0.TemperatureC != 71 {
		t.Errorf("GPU 0 parsed incorrectly: %+v", g0)
	}
	if gpus[1].Index != 1 || gpus[1].UUID != "GPU-bbbb" {
		t.Errorf("GPU 1 parsed incorrectly: %+v", gpus[1])
	}
}

func TestParseGPUCSV_Empty(t *testing.T) {
	gpus, err := ParseGPUCSV("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(gpus) != 0 {
		t.Errorf("expected empty slice, got %d entries", len(gpus))
	}
}

func TestParseGPUCSV_WrongFieldCount(t *testing.T) {
	_, err := ParseGPUCSV("0, GPU-aaaa, only-three-fields")
	if err == nil {
		t.Fatal("expected error for wrong field count, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected gpu field count") {
		t.Errorf("error does not mention field count: %v", err)
	}
}

func TestParseGPUCSV_InvalidIndex(t *testing.T) {
	raw := `notanumber, GPU-aaaa, 0000:01:00.0, RTX 3090, 24576 MiB, 4096 MiB, 73 %, 71`
	_, err := ParseGPUCSV(raw)
	if err == nil {
		t.Fatal("expected parse error for invalid index")
	}
	if !strings.Contains(err.Error(), "parse gpu index") {
		t.Errorf("error does not mention gpu index: %v", err)
	}
}

func TestParseComputeAppsCSV_HappyPath(t *testing.T) {
	raw := `GPU-aaaa, 12345, python3, 2048 MiB
GPU-bbbb, 67890, vllm, 4096 MiB
GPU-aaaa, 11111, ollama, [N/A]`
	processes, err := ParseComputeAppsCSV(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(processes["GPU-aaaa"]) != 2 {
		t.Errorf("expected 2 processes on GPU-aaaa, got %d", len(processes["GPU-aaaa"]))
	}
	if len(processes["GPU-bbbb"]) != 1 {
		t.Errorf("expected 1 process on GPU-bbbb, got %d", len(processes["GPU-bbbb"]))
	}
	p0 := processes["GPU-aaaa"][0]
	if p0.PID != 12345 || p0.ProcessName != "python3" || p0.UsedMemoryMiB != 2048 {
		t.Errorf("first process on GPU-aaaa wrong: %+v", p0)
	}
	// [N/A] should be normalised to 0
	if processes["GPU-aaaa"][1].UsedMemoryMiB != 0 {
		t.Errorf("[N/A] should be 0, got %d", processes["GPU-aaaa"][1].UsedMemoryMiB)
	}
}

func TestParseComputeAppsCSV_Empty(t *testing.T) {
	processes, err := ParseComputeAppsCSV("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(processes) != 0 {
		t.Errorf("expected empty map, got %d entries", len(processes))
	}
}

func TestParseComputeAppsCSV_WrongFieldCount(t *testing.T) {
	_, err := ParseComputeAppsCSV("GPU-aaaa, 12345, only-three-fields")
	if err == nil {
		t.Fatal("expected error for wrong field count")
	}
	if !strings.Contains(err.Error(), "unexpected compute app field count") {
		t.Errorf("error does not mention compute app field count: %v", err)
	}
}

func TestAttachProcesses_MergesByUUID(t *testing.T) {
	gpus := []Snapshot{
		{Index: 0, UUID: "GPU-aaaa"},
		{Index: 1, UUID: "GPU-bbbb"},
		{Index: 2, UUID: "GPU-cccc"},
	}
	processes := map[string][]Process{
		"GPU-aaaa": {{PID: 100, ProcessName: "python", UsedMemoryMiB: 512}},
		"GPU-cccc": {{PID: 200, ProcessName: "vllm", UsedMemoryMiB: 1024}},
	}
	merged := AttachProcesses(gpus, processes)
	if len(merged) != 3 {
		t.Fatalf("expected 3 merged snapshots, got %d", len(merged))
	}
	// GPU-bbbb has no processes — Processes should be nil
	if merged[1].Processes != nil {
		t.Errorf("GPU-bbbb should have nil processes, got %+v", merged[1].Processes)
	}
	if len(merged[0].Processes) != 1 || merged[0].Processes[0].PID != 100 {
		t.Errorf("GPU-aaaa processes not attached correctly: %+v", merged[0].Processes)
	}
	// Original slice should not be mutated
	if len(gpus[0].Processes) != 0 {
		t.Errorf("original GPU-aaaa was mutated: %+v", gpus[0].Processes)
	}
}

func TestAttachProcesses_NoMatches(t *testing.T) {
	gpus := []Snapshot{{Index: 0, UUID: "GPU-aaaa"}}
	merged := AttachProcesses(gpus, map[string][]Process{})
	if merged[0].Processes != nil {
		t.Errorf("expected nil processes, got %+v", merged[0].Processes)
	}
}

func TestCollectSnapshots_EndToEnd(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch {
		case strings.Contains(strings.Join(args, " "), "query-gpu"):
			return []byte(`0, GPU-aaaa, 0000:01:00.0, RTX 3090, 24576 MiB, 4096 MiB, 73 %, 71`), nil
		case strings.Contains(strings.Join(args, " "), "query-compute-apps"):
			return []byte(`GPU-aaaa, 12345, python3, 2048 MiB`), nil
		}
		return nil, nil
	}
	snapshots, err := CollectSnapshots(context.Background(), runner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(snapshots))
	}
	if snapshots[0].UUID != "GPU-aaaa" || snapshots[0].Index != 0 {
		t.Errorf("snapshot UUID/Index wrong: %+v", snapshots[0])
	}
	if len(snapshots[0].Processes) != 1 || snapshots[0].Processes[0].PID != 12345 {
		t.Errorf("processes not attached: %+v", snapshots[0].Processes)
	}
}

func TestCollectSnapshots_GPUQueryFails(t *testing.T) {
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, &fakeErr{msg: "nvidia-smi not found"}
	}
	_, err := CollectSnapshots(context.Background(), runner)
	if err == nil {
		t.Fatal("expected error when nvidia-smi fails")
	}
}

func TestCollectSnapshots_ComputeQueryFails(t *testing.T) {
	calls := 0
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte(`0, GPU-aaaa, 0000:01:00.0, RTX 3090, 24576 MiB, 4096 MiB, 73 %, 71`), nil
		}
		return nil, &fakeErr{msg: "compute query failed"}
	}
	_, err := CollectSnapshots(context.Background(), runner)
	if err == nil {
		t.Fatal("expected error when compute-apps query fails")
	}
}

func TestParseMetricInt_WithSuffixes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"4096 MiB", 4096},
		{"73 %", 73},
		{"  100  ", 100},
		{"MiB", 0}, // edge: just the suffix stripped → empty → parse error → 0
	}
	for _, c := range cases {
		got, err := parseMetricInt(c.in)
		if err != nil {
			// last case is expected to fail; skip
			if c.in == "MiB" {
				continue
			}
			t.Errorf("parseMetricInt(%q) returned err: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseMetricInt(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseOptionalMetricInt_NAValues(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"   ", 0, false},
		{"N/A", 0, false},
		{"[N/A]", 0, false},
		{"1024 MiB", 1024, false},
	}
	for _, c := range cases {
		got, err := parseOptionalMetricInt(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseOptionalMetricInt(%q) err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("parseOptionalMetricInt(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// fakeErr is a minimal error type for runner tests.
type fakeErr struct{ msg string }

func (e *fakeErr) Error() string { return e.msg }
