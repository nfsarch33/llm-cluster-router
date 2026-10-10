// Package relcheck compares a tool's build version against the newest
// upstream tag and WARNS — never blocks — when the binary is outdated.
//
// Fleet rule: every distributed tool self-checks its version "from time to
// time" and surfaces a warning without interrupting execution. This package
// is the reference implementation; other tools (runx, helix-dev-tools,
// helixchannel) adopt the same shape.
//
// Design choices, so the check can never hurt availability:
//   - async: callers run WarnIfOutdated in a goroutine at startup.
//   - warn-only: no error escapes to the caller's control flow.
//   - cached: the latest-tag answer is cached on disk for CacheTTL so a
//     fleet of restarts cannot rate-limit us against the GitHub API.
//   - short timeout: one 5s HTTP attempt; failure just means "no warning".
//   - dev builds ("", "dev", "-dirty" suffixed) are never warned about.
package relcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CacheTTL bounds how often a running fleet re-asks GitHub for the latest tag.
const CacheTTL = 24 * time.Hour

// APIBase is swappable for tests.
var APIBase = "https://api.github.com"

// Result describes one comparison.
type Result struct {
	Current  string `json:"current"`
	Latest   string `json:"latest"`
	Outdated bool   `json:"outdated"`
}

type cacheEntry struct {
	Latest    string    `json:"latest"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Check resolves the newest tag of owner/repo (tags endpoint — our repos tag
// releases without GitHub Release objects, where /releases/latest would 404)
// and compares it to current. cacheDir may be "" to disable caching.
func Check(ctx context.Context, owner, repo, current, cacheDir string) (Result, error) {
	res := Result{Current: current}
	if skippable(current) {
		return res, nil
	}
	latest, err := latestTag(ctx, owner, repo, cacheDir)
	if err != nil {
		return res, err
	}
	res.Latest = latest
	res.Outdated = latest != "" && normalize(latest) != normalize(current)
	return res, nil
}

// WarnIfOutdated is the fire-and-forget form used at tool startup:
//
//	go relcheck.WarnIfOutdated(logger, "nfsarch33", "llm-cluster-router", buildVersion)
//
// It never panics, never blocks the caller, and only ever emits one WARN line.
func WarnIfOutdated(logger *slog.Logger, owner, repo, current string) {
	defer func() { _ = recover() }() // a version nag must never take the tool down
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	res, err := Check(ctx, owner, repo, current, defaultCacheDir())
	if err != nil || logger == nil {
		return
	}
	if res.Outdated {
		logger.Warn("a newer release of this tool is available — consider updating (execution continues)",
			"tool", repo, "running", res.Current, "latest", res.Latest)
	}
}

// aheadOfTag matches git-describe output for commits past a tag
// (v1.0.0-11-gabc123): effectively a dev build — warning would be noise.
var aheadOfTag = regexp.MustCompile(`-[0-9]+-g[0-9a-f]+(-dirty)?$`)

func skippable(current string) bool {
	c := strings.TrimSpace(current)
	return c == "" || c == "dev" || strings.HasSuffix(c, "-dirty") || aheadOfTag.MatchString(c)
}

func normalize(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "v") }

func defaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "helixon", "relcheck")
}

func latestTag(ctx context.Context, owner, repo, cacheDir string) (string, error) {
	cachePath := ""
	if cacheDir != "" {
		cachePath = filepath.Join(cacheDir, owner+"_"+repo+".json")
		if raw, err := os.ReadFile(cachePath); err == nil {
			var e cacheEntry
			if json.Unmarshal(raw, &e) == nil && time.Since(e.FetchedAt) < CacheTTL {
				return e.Latest, nil
			}
		}
	}

	url := fmt.Sprintf("%s/repos/%s/%s/tags?per_page=1", APIBase, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tags endpoint: %s", resp.Status)
	}
	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", nil
	}
	latest := tags[0].Name

	if cachePath != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err == nil {
			raw, _ := json.Marshal(cacheEntry{Latest: latest, FetchedAt: time.Now()})
			_ = os.WriteFile(cachePath, raw, 0o644)
		}
	}
	return latest, nil
}
