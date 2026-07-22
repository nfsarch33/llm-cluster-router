package main

import "testing"

// TestSessionOutcomeFromStatus asserts the v18714-3 outcome mapping
// for HelixChannel sessions. Locks the canonical 5 outcomes and
// the rule that 5xx → "failure" and 2xx → "success".
func TestSessionOutcomeFromStatus(t *testing.T) {
	cases := []struct {
		status int
		want   string
	}{
		{200, "success"},
		{201, "success"},
		{204, "success"},
		{299, "success"},
		{301, "closed"},
		{302, "closed"},
		{400, "closed"},
		{404, "closed"},
		{499, "closed"},
		{500, "failure"},
		{502, "failure"},
		{599, "failure"},
	}
	for _, tc := range cases {
		got := sessionOutcomeFromStatus(tc.status)
		if got != tc.want {
			t.Errorf("status %d: want %q, got %q", tc.status, tc.want, got)
		}
	}
}
