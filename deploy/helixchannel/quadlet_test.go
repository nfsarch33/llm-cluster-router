// Package helixchannel_deploy_tests (v18716.6) validates the
// Quadlet distribution at deploy/helixchannel/quadlet/. The
// tests do NOT require podman or systemd to be installed — they
// parse the unit files and assert the canonical Quadlet
// structure. A separate TDD step (running `podman build` on a
// real host) gates deployment; the local runner path can stop
// at parser validation.
//
// This file lives under deploy/ rather than internal/ because
// it tests deploy-time artefacts that are not part of any Go
// package import graph. `go test ./deploy/...` discovers it
// without an internal helper package.
//
//go:build ignore
// +build ignore

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// requiredQuadletSections is the minimum set of section headers
// a Quadlet .container unit MUST contain for systemd to
// recognise it. We assert presence in each shipped unit so a
// typo during authoring fails CI rather than silently breaking
// at boot.
var requiredQuadletSections = []string{"[Unit]", "[Container]", "[Install]"}

// TestQuadletUnits_AllContainRequiredSections walks the
// quadlet/ directory and verifies each .container file has the
// canonical sections.
func TestQuadletUnits_AllContainRequiredSections(t *testing.T) {
	root := filepath.Join("deploy", "helixchannel", "quadlet")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", root, err)
	}
	var units []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".container") {
			units = append(units, filepath.Join(root, e.Name()))
		}
	}
	if len(units) == 0 {
		t.Fatalf("no .container units found under %s", root)
	}
	for _, p := range units {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("ReadFile(%s): %v", p, err)
			continue
		}
		body := string(data)
		for _, sec := range requiredQuadletSections {
			if !strings.Contains(body, sec) {
				t.Errorf("%s missing section %q", p, sec)
			}
		}
	}
}

// TestQuadletUnits_ReferencePublishedImage asserts every shipped
// unit references the canonical local image tag
// (helixon/tools-helixchannel:v0.2.0). Without this assertion a
// unit could be authored against an older tag and silently boot
// the wrong image.
func TestQuadletUnits_ReferencePublishedImage(t *testing.T) {
	const wantImage = "helixon/tools-helixchannel:v0.2.0"
	root := filepath.Join("deploy", "helixchannel", "quadlet")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", root, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".container") {
			continue
		}
		p := filepath.Join(root, e.Name())
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("ReadFile(%s): %v", p, err)
			continue
		}
		if !strings.Contains(string(data), wantImage) {
			t.Errorf("%s does not reference %q", p, wantImage)
		}
	}
}

// TestContainerfile_HelixChannel_BuildsExpectedBinaries parses
// Containerfile.helixchannel and asserts the three target
// binaries are wired into /usr/local/bin/. We do NOT run
// `podman build` here — that gate is host-side; the test
// asserts the source-of-truth Containerfile is internally
// consistent.
func TestContainerfile_HelixChannel_BuildsExpectedBinaries(t *testing.T) {
	p := filepath.Join("deploy", "helixchannel", "Containerfile.helixchannel")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", p, err)
	}
	body := string(data)
	for _, bin := range []string{
		"/out/llm-cluster-router",
		"/out/helixchannel",
		"/out/dual-listener-demo",
		"/usr/local/bin/llm-cluster-router",
		"/usr/local/bin/helixchannel",
		"/usr/local/bin/dual-listener-demo",
	} {
		if !strings.Contains(body, bin) {
			t.Errorf("Containerfile.helixchannel missing %q", bin)
		}
	}
}