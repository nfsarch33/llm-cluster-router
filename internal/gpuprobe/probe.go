// Package gpuprobe implements nvidia-smi CSV parsing and GPU
// snapshot collection for the probe-gpu subcommand.
package gpuprobe

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Process describes a single process using GPU memory.
type Process struct {
	PID           int    `json:"pid"`
	ProcessName   string `json:"process_name"`
	UsedMemoryMiB int    `json:"used_memory_mib"`
}

// Snapshot captures a point-in-time view of a single GPU.
type Snapshot struct {
	Index          int       `json:"index"`
	UUID           string    `json:"uuid"`
	PCIBusID       string    `json:"pci_bus_id"`
	Name           string    `json:"name"`
	MemoryTotalMiB int       `json:"memory_total_mib"`
	MemoryUsedMiB  int       `json:"memory_used_mib"`
	UtilizationGPU int       `json:"utilization_gpu_pct"`
	TemperatureC   int       `json:"temperature_c"`
	Processes      []Process `json:"processes,omitempty"`
}

// Report is the top-level output of the probe-gpu subcommand.
type Report struct {
	CapturedAt string     `json:"captured_at"`
	GPUs       []Snapshot `json:"gpus"`
}

// CommandRunner abstracts exec.Command for testability.
type CommandRunner func(context.Context, string, ...string) ([]byte, error)

// CollectSnapshots runs nvidia-smi and returns parsed GPU state.
func CollectSnapshots(ctx context.Context, runner CommandRunner) ([]Snapshot, error) {
	gpuCSV, err := runner(ctx, "nvidia-smi",
		"--query-gpu=index,uuid,pci.bus_id,name,memory.total,memory.used,utilization.gpu,temperature.gpu",
		"--format=csv,noheader",
	)
	if err != nil {
		return nil, err
	}
	gpus, err := ParseGPUCSV(string(gpuCSV))
	if err != nil {
		return nil, err
	}

	computeCSV, err := runner(ctx, "nvidia-smi",
		"--query-compute-apps=gpu_uuid,pid,process_name,used_memory",
		"--format=csv,noheader",
	)
	if err != nil {
		return nil, err
	}
	processes, err := ParseComputeAppsCSV(string(computeCSV))
	if err != nil {
		return nil, err
	}
	return AttachProcesses(gpus, processes), nil
}

// ParseGPUCSV parses nvidia-smi GPU query CSV output.
func ParseGPUCSV(raw string) ([]Snapshot, error) {
	lines := splitCSVLines(raw)
	gpus := make([]Snapshot, 0, len(lines))
	for _, line := range lines {
		fields := splitCSVFields(line)
		if len(fields) != 8 {
			return nil, fmt.Errorf("unexpected gpu field count %d in %q", len(fields), line)
		}

		index, err := parseMetricInt(fields[0])
		if err != nil {
			return nil, fmt.Errorf("parse gpu index: %w", err)
		}
		memoryTotal, err := parseMetricInt(fields[4])
		if err != nil {
			return nil, fmt.Errorf("parse total memory: %w", err)
		}
		memoryUsed, err := parseMetricInt(fields[5])
		if err != nil {
			return nil, fmt.Errorf("parse used memory: %w", err)
		}
		utilization, err := parseMetricInt(fields[6])
		if err != nil {
			return nil, fmt.Errorf("parse utilization: %w", err)
		}
		temperature, err := parseMetricInt(fields[7])
		if err != nil {
			return nil, fmt.Errorf("parse temperature: %w", err)
		}

		gpus = append(gpus, Snapshot{
			Index:          index,
			UUID:           fields[1],
			PCIBusID:       fields[2],
			Name:           fields[3],
			MemoryTotalMiB: memoryTotal,
			MemoryUsedMiB:  memoryUsed,
			UtilizationGPU: utilization,
			TemperatureC:   temperature,
		})
	}
	return gpus, nil
}

// ParseComputeAppsCSV parses nvidia-smi compute-apps CSV.
func ParseComputeAppsCSV(raw string) (map[string][]Process, error) {
	lines := splitCSVLines(raw)
	processes := make(map[string][]Process)
	for _, line := range lines {
		fields := splitCSVFields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("unexpected compute app field count %d in %q", len(fields), line)
		}

		pid, err := parseMetricInt(fields[1])
		if err != nil {
			return nil, fmt.Errorf("parse pid: %w", err)
		}
		usedMemory, err := parseOptionalMetricInt(fields[3])
		if err != nil {
			return nil, fmt.Errorf("parse process memory: %w", err)
		}

		processes[fields[0]] = append(processes[fields[0]], Process{
			PID:           pid,
			ProcessName:   fields[2],
			UsedMemoryMiB: usedMemory,
		})
	}
	return processes, nil
}

// AttachProcesses merges process lists into GPU snapshots by UUID.
func AttachProcesses(gpus []Snapshot, processes map[string][]Process) []Snapshot {
	merged := make([]Snapshot, len(gpus))
	copy(merged, gpus)
	for i := range merged {
		merged[i].Processes = processes[merged[i].UUID]
	}
	return merged
}

func splitCSVLines(raw string) []string {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		filtered = append(filtered, line)
	}
	return filtered
}

func splitCSVFields(line string) []string {
	parts := strings.Split(line, ",")
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		fields = append(fields, strings.TrimSpace(part))
	}
	return fields
}

func parseMetricInt(raw string) (int, error) {
	cleaned := strings.TrimSpace(raw)
	for _, suffix := range []string{"MiB", "%"} {
		cleaned = strings.TrimSpace(strings.TrimSuffix(cleaned, suffix))
	}
	return strconv.Atoi(cleaned)
}

func parseOptionalMetricInt(raw string) (int, error) {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" || cleaned == "N/A" || cleaned == "[N/A]" {
		return 0, nil
	}
	return parseMetricInt(cleaned)
}
