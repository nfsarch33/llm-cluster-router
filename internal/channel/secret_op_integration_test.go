//go:build integration

package channel

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestIT_OnePasswordProvider_ExecPath_ResolvesViaStubBinary exercises the real
// execOPRead code path — the one place in package channel that starts a
// process — without a 1Password account, a vault or a network.
//
// The argv contract is what is actually under test: the stub only answers
// `read --no-newline op://example-vault/example-item/credential` and exits 2
// for anything else, so reordering the arguments or dropping --no-newline
// turns this test red rather than silently changing what the gateway asks for.
func TestIT_OnePasswordProvider_ExecPath_ResolvesViaStubBinary(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("stub executable relies on a POSIX shebang; GOOS = %s", runtime.GOOS)
	}

	dir := t.TempDir()
	stub := filepath.Join(dir, "op")
	script := `#!/bin/sh
if [ "$1" = "read" ] && [ "$2" = "--no-newline" ] && [ "$3" = "op://example-vault/example-item/credential" ] && [ "$#" -eq 3 ]; then
  printf '%s' 'test-key-not-real'
  exit 0
fi
printf 'unexpected argv: %s\n' "$*" >&2
exit 2
`
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil {
		t.Fatalf("write stub op: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	p := newOnePasswordProvider()
	p.timeout = 30 * time.Second

	got, err := p.Resolve("op://example-vault/example-item/credential")
	if err != nil {
		t.Fatalf("Resolve through the real exec path: %v", err)
	}
	if got != "test-key-not-real" {
		t.Fatalf("Resolve() = %q, want %q (a real CLI would not return this)", got, "test-key-not-real")
	}

	// A reference the stub does not recognise must surface as a classified,
	// non-secret failure carrying the exit code.
	_, err = p.Resolve("op://example-vault/other-item/credential")
	if err == nil {
		t.Fatal("Resolve() = nil error for an unknown reference, want ErrSecretUnavailable")
	}
	if !errors.Is(err, ErrSecretUnavailable) {
		t.Errorf("errors.Is(err, ErrSecretUnavailable) = false, err = %v", err)
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error %q does not report the stub's exit code 2", err)
	}
}
