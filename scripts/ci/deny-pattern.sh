#!/usr/bin/env bash
# runx-public-repo-gate: allow-file private_key
# v18750-O-Track-D: deny-pattern anti-leak scanner
#
# Scans git diff (against base ref) for forbidden patterns: 1Password vault
# names, internal IPs, PII keys, API tokens, security keys, etc.
#
# v18794 — the allow-file header on line 2 is for a DIFFERENT gate, and it has
# to stay on line 2. helixon-platform's .github/scripts/public-repo-gate.sh
# greps its tree for the literal `ssh-rsa ` under the category `private_key`,
# and the PATTERNS array below carries that literal as a REGEX DESCRIBING the
# format -- there is no key material in this file. So the first commit that
# installed this scanner into helixon-platform failed that repo's gate on the
# artefact it was adding, which is the same shape as the self-match v18792
# fixed, one scanner's pattern list tripping another scanner.
#
# The annotation is the mechanism that gate documents and that twelve files in
# helixon-platform already use; the alternative was splitting the literal to
# dodge a grep, which is obfuscation and would leave the pattern less readable
# than the thing it detects. It must appear within the first
# PUBLIC_REPO_GATE_HEADER_LINES (default 5) lines or it is not consulted --
# tools/deny-pattern-tests.sh pins both the header and that line budget.
#
# Usage:
#   bash deny-pattern.sh [BASE_REF]
#     BASE_REF defaults to origin/main (or HEAD~1 if no origin)
#
# Exit codes:
#   0 — nothing to scan, no matches, or this IS the internal repo
#   1 — at least one match found (fail the workflow / pre-push)
#   2 — configuration error (missing base, git failure)
#
# This script is the canonical scanner; it's invoked by:
#   - .github/workflows/deny-pattern.yml (PR check, no GH Actions minutes)
#   - .git/hooks/pre-push (local pre-push, instant feedback)
#   - L0 rule 01-public-repo-sanity.mdc (AI agent auto-check before commit)
#
# v18790 — two defects fixed. Both made this gate report something other than
# what it had actually done, and both reproduced on pristine main @659deaa9d.
#
#   1. INTERNAL_REPO was decided by a GLOB OVER THE WORKING-DIRECTORY PATH:
#        case "$(git rev-parse --show-toplevel)" in *cursor-global-kb*)
#      so ANY repo checked out beneath a directory whose name contains
#      "cursor-global-kb" bypassed every deny pattern — vault names, Tailscale
#      IPs, PATs, Slack tokens, operator emails — and a legitimate KB worktree
#      at a path that did not carry the name failed to bypass. Repo identity
#      now comes from the repo: the origin remote's owner/repo slug, with a
#      tracked marker file as the fallback. The checkout path decides nothing.
#
#   2. `DIFF=$(... | grep -E '^\+' | grep -v '^+++')` died under
#      `set -o pipefail` whenever the diff added no lines — grep exits 1 — so
#      the script exited 1 having printed one line and scanned nothing, and
#      the "No diff to scan" branch below it was unreachable. Every caller
#      read that as "anti-leak scan FAILED". The empty case now says so and
#      exits 0; a base ref that does not resolve is a genuine configuration
#      error and exits 2, so the fail-closed direction is kept where it belongs.
#
# v18791 — the third of the same family, left out of scope by #875 and fixed
# here. `FOUND` was a 0/1 flag that the summary printed as if it were a count:
#
#     FOUND=1                                    # in the per-pattern loop
#     echo "FAIL: $FOUND pattern match(es) ..."  # in the summary
#
# so a run that had just printed four MATCH blocks — a vault name, an op://
# reference, a Tailscale IP and an operator email — still signed off with
# "FAIL: 1 pattern match(es)". Reproduced on pristine main @4f0aa9a7b. The
# blocks were right and only the summary was wrong, but the summary is the
# line that gets quoted into a PR comment, a hook failure and a runbook, so
# the gate consistently understated what it had found. It is a real counter
# now, and each block reports its own line count and says when the three-line
# cap hid some.
#
# v18792 — the fourth, and the reason the installer had never been run. Seven
# PATTERNS entries were plain literal strings, because that is what a pattern
# list is, so the commit that ADDS this file to a public repo matched seven of
# its own patterns — reproduced on pristine main @4f0aa9a7b: 7 MATCH blocks,
# exit 1. (The seven are no longer named here: see v18793 below — this file is
# installed into public repositories, and an enumeration of them is exactly
# the thing that must not travel.) The pull
# request that installs the gate went red on the artefact it was adding, and
# the installed pre-push hook blocked the very push that installs it. The only
# way past was --no-verify, which L0 rule 01-public-repo-sanity.mdc forbids and
# should, so scripts/ci/install-deny-pattern.sh could never be run against
# helixon-platform or llm-cluster-router — the two public repos, and the entire
# point of the installer. This scanner's own source is now excluded from the
# diff it reads; see SELF_PATH below for the shape of that exclusion and
# docs/security/anti-leak.md for what still covers the excluded file.
#
# v18793 — the fifth, and the one that had to land before the installer was
# ever pointed at a public repository. This file's PATTERNS array IS a list of
# the identifiers that name this estate: a 1Password vault name, an SA token
# name, two operator email addresses, an internal host-naming scheme, an agent
# name. Installing the gate into a public repo published that list — a curated,
# machine-readable index of exactly what an attacker should grep the estate's
# public artefacts for. Measured 2026-08-31 against origin/main: for
# llm-cluster-router seven of them, including BOTH operator email addresses,
# would have been NEW disclosure.
#
# So the patterns are now in two sets:
#
#   PUBLIC   — vendor credential FORMATS (AWS, GitHub, Slack, Stripe, SSH keys)
#              and the generic private-address ranges. None of these names this
#              estate; they are safe in a public tree, and they are the ones a
#              real credential leak trips.
#   INTERNAL — everything that identifies this estate. Kept OUT of this file
#              and loaded at runtime from HLXN_DENY_PATTERNS_FILE, which points
#              at a file that only ever exists where it is already private: the
#              knowledge base checkout (for the local pre-push hook) or an
#              Actions secret materialised on the runner (for CI).
#
# The run always says which sets it loaded. An unset HLXN_DENY_PATTERNS_FILE is
# a legitimate, announced reduction in coverage; a SET-but-unreadable one is a
# configuration error and exits 2, because "the internal set was configured and
# silently did not load" must never look like "the internal set is not
# configured".
#
# INTERNAL_SLUG below stays a literal on purpose. The owner handle appears in
# every clone URL of these repos and `cursor-global-kb` is already in 70 files
# of helixon-platform and 10 of llm-cluster-router (measured 2026-08-31), so it
# discloses nothing new — and hashing it would rewrite the exemption logic
# v18790 fixed and that tools/deny-pattern-tests.sh pins in both directions.
#
# v18797 — the sixth. The operator GitHub handle is an internal deny pattern,
# and the handle is ALSO the owner segment of every one of these repos' OWN
# module paths (github.com/nfsarch33/<this-repo>), which sit on go.mod and on
# every internal import. So a diff that added a new internal import tripped the
# handle pattern on a string the repo is public by construction for carrying —
# llm-cluster-router PR #73, and every future PR to either public repo that
# adds an internal import. The scanner now removes exactly that one public slug
# (this repo's own github.com/<owner>/<repo>, at a path boundary) from the added
# lines before matching; a reference to any OTHER repo under the same handle,
# including a private one, is untouched and still caught. See the SCAN_DIFF
# block below and docs/security/anti-leak.md.
#
# v18811 — the seventh, and the only one this file caused itself. v18797 above
# matched EVERY pattern against the shortened lines, so any pattern whose match
# had to run past the slug went silent: an SSH public key whose comment ended
# at the repo's own module path passed the gate, in both public repos, with the
# public set alone. The removal is now applied per pattern — only to a pattern
# the module path would itself match — and leaves a separator behind. See the
# v18811 note in the SCAN_DIFF block below.
#
# Regression pins: tools/deny-pattern-tests.sh (registered in
# tools/workspace-doctor.sh). The installer that ships this scanner into other
# repos is pinned by tools/install-deny-pattern-tests.sh.

set -euo pipefail

# The single repository whose contents are exempt. It is internal and holds
# operator handles, internal IPs and host names by design.
INTERNAL_SLUG="nfsarch33/cursor-global-kb"
INTERNAL_MARKER=".internal-repo"

# The one path this scanner does not scan: its own source. See the v18792 note
# above for why. This narrows a security predicate, so it is deliberately the
# smallest and dumbest narrowing that fixes the defect:
#
#   * ONE path, spelled out as a fixed literal here in the scanner. Never a
#     glob, never a directory, never read from the environment, an argument, or
#     the diff being scanned. A gate whose exempt paths can be named by the
#     diff it is scanning is not a gate.
#   * `top,` anchors the pathspec to the repository ROOT. Without it a pathspec
#     resolves against the CURRENT DIRECTORY, and the pre-push hook runs
#     wherever the operator happened to type `git push`. Measured 2026-08-31
#     from scripts/ci/: a bare ':(exclude)scripts/ci/deny-pattern.sh' excludes
#     nothing, and the ':(exclude)' form written alongside a '.' pathspec scans
#     only the current directory and silently drops the rest of the repo — a
#     gate that passes because it never looked. Both are pinned in
#     tools/install-deny-pattern-tests.sh.
#   * Everything else is still scanned, including every other file in
#     scripts/ci/ and any other file with this basename elsewhere in the tree.
#     An exclusion that swallows a directory is worse than the self-match it
#     fixes, and would look identical in a test that only asserts "exit 0".
#
# If this file is ever renamed, the exclusion stops applying and the scanner
# starts matching its own source again: loud, and in the safe direction.
SELF_PATH="scripts/ci/deny-pattern.sh"
SELF_EXCLUDE=":(top,exclude)$SELF_PATH"

BASE_REF="${1:-}"

# Determine base ref
if [[ -z "$BASE_REF" ]]; then
  if git rev-parse --verify origin/main >/dev/null 2>&1; then
    BASE_REF="origin/main"
  elif git rev-parse --verify origin/master >/dev/null 2>&1; then
    BASE_REF="origin/master"
  elif git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
    BASE_REF="HEAD~1"
  else
    echo "ERROR: cannot determine BASE_REF; pass it as arg 1" >&2
    exit 2
  fi
fi

# v18750-Q9 / v18790: INTERNAL_REPO detection for cursor-global-kb.
#
# Per L0 rule 01-public-repo-sanity.mdc, cursor-global-kb is an internal repo
# that may contain operator hostnames, internal IPs and operator GitHub
# handles. When the scanner runs inside THAT repo, the deny patterns are
# bypassed. Identity is established from the repository itself, never from
# where it happens to be checked out.

# Print the owner/repo slug of the origin remote, or fail if origin is absent
# or is not a github.com URL. The host is matched after stripping scheme and
# userinfo, so `https://github.com.evil.example/nfsarch33/cursor-global-kb`
# and `https://evil.example/github.com/nfsarch33/cursor-global-kb` both fail
# rather than resolving to the internal slug.
repo_slug_from_origin() {
  local url rest slug
  url="$(git config --get remote.origin.url 2>/dev/null)" || return 1
  [[ -n "$url" ]] || return 1
  url="${url%/}"
  url="${url%.git}"
  rest="${url#*://}"   # drop scheme, if any (scp-like URLs have none)
  rest="${rest#*@}"    # drop userinfo, if any
  case "$rest" in
    github.com:*) slug="${rest#github.com:}" ;;
    github.com/*) slug="${rest#github.com/}" ;;
    *) return 1 ;;
  esac
  slug="${slug#/}"
  # Exactly one slash: owner/repo, nothing deeper.
  [[ "$slug" == */* && "$slug" != */*/* ]] || return 1
  printf '%s\n' "$slug"
}

# The fallback for clones whose origin is a mirror, a bare path, or absent —
# an offline mirror, an archive re-init, a checkout with the remote removed.
# The marker must be TRACKED (so it went through review, not dropped in) and
# must carry the slug on a line of its own.
marker_declares_internal() {
  local top="$1"
  [[ -f "$top/$INTERNAL_MARKER" ]] || return 1
  git -C "$top" ls-files --error-unmatch -- "$INTERNAL_MARKER" \
    >/dev/null 2>&1 || return 1
  # tr -d '\r': .gitattributes pins this file to LF, but a checkout made
  # before that pin (or with core.autocrlf on) would carry CRLF, and the
  # whole-line match would silently stop resolving.
  tr -d '\r' <"$top/$INTERNAL_MARKER" 2>/dev/null \
    | grep -qxF "$INTERNAL_SLUG" || return 1
  return 0
}

INTERNAL_REPO=0
IDENTITY_SOURCE=""
REPO_SLUG=""
if REPO_TOP="$(git rev-parse --show-toplevel 2>/dev/null)"; then
  REPO_SLUG="$(repo_slug_from_origin || true)"
  if [[ "$REPO_SLUG" == "$INTERNAL_SLUG" ]]; then
    INTERNAL_REPO=1
    IDENTITY_SOURCE="origin remote"
  elif marker_declares_internal "$REPO_TOP"; then
    INTERNAL_REPO=1
    IDENTITY_SOURCE="tracked $INTERNAL_MARKER marker"
  fi
fi

if [[ "$INTERNAL_REPO" -eq 1 ]]; then
  echo "OK: INTERNAL_REPO $INTERNAL_SLUG via $IDENTITY_SOURCE - deny-pattern skipped (L0 rule 01-public-repo-sanity.mdc)"
  exit 0
fi

# Say which repo is being scanned and why it was not exempted. The old script
# printed nothing here, so a wrongly-exempted or wrongly-scanned run looked
# identical to a correct one. The slug is deliberate: the checkout path is
# never printed, because this scanner's own output ends up in public CI logs.
echo "Repo identity: ${REPO_SLUG:-<no github.com origin remote>} (not $INTERNAL_SLUG) - scanning"
echo "Scanning diff against $BASE_REF ..."
# Say it out loud. A gate that quietly scans less than it claims is the failure
# mode this whole file keeps rediscovering, so the one exempt path is named on
# every run rather than left in the source for someone to find later.
echo "Excluding $SELF_PATH (this scanner's own source; see docs/security/anti-leak.md)"

# A base ref that does not resolve means NOTHING was scanned. That is a
# configuration error (exit 2), and it must stay distinguishable from a clean
# scan — otherwise the empty-diff fix below would turn a broken invocation
# into a silent pass.
if ! git rev-parse --verify --quiet "${BASE_REF}^{commit}" >/dev/null 2>&1; then
  echo "ERROR: BASE_REF '$BASE_REF' does not resolve to a commit in this repo;" >&2
  echo "       nothing was scanned. Fetch it (git fetch origin <branch>) or" >&2
  echo "       pass a ref that exists." >&2
  exit 2
fi

# Diff against base ref
# Only scan ADDED lines (start with +). Removed lines (-) are intentionally
# not scanned because they represent content that is LEAVING the codebase,
# which is harmless from a leak-prevention standpoint.
if RAW_DIFF="$(git diff "$BASE_REF"...HEAD -- "$SELF_EXCLUDE" 2>/dev/null)"; then
  :
elif RAW_DIFF="$(git diff "$BASE_REF" HEAD -- "$SELF_EXCLUDE" 2>/dev/null)"; then
  echo "NOTE: no merge base with $BASE_REF; scanning the two-dot diff instead."
else
  echo "ERROR: git diff against '$BASE_REF' failed; nothing was scanned." >&2
  exit 2
fi

# `|| true`: with no added lines both greps exit 1, which under
# `set -o pipefail` used to kill the script here, one line into its output.
DIFF="$(printf '%s\n' "$RAW_DIFF" | grep -E '^\+' | grep -v '^+++' || true)"

if [[ -z "$DIFF" ]]; then
  # Since v18792 there are two ways to land here, and the message must not
  # claim the wrong one: a genuinely empty range, or a range whose only added
  # lines were in the one excluded path.
  echo "OK: no added lines in diff against $BASE_REF - nothing to scan (empty range, or only $SELF_PATH changed)"
  exit 0
fi

# v18797 — neutralize the repo's OWN public module path before matching.
#
# The operator GitHub handle is an internal deny pattern, but that handle is
# ALSO the owner segment of every one of these repos' own module paths:
# `github.com/nfsarch33/<this-repo>`. That path sits on go.mod's `module` line,
# on every `require`, and on every internal import, so it is public BY
# CONSTRUCTION in the repo it names — yet a diff that adds a NEW internal import
# (e.g. `"github.com/nfsarch33/llm-cluster-router/internal/crypto"`) tripped the
# handle pattern on a string the repo could not not contain. Measured
# 2026-08-31: llm-cluster-router PR #73 failed exactly this way, and so would
# every future PR to either public repo that adds an internal import.
#
# So the one string that is public by construction — this repo's own
# `github.com/<owner>/<repo>` slug, and ONLY that exact slug at a path boundary
# — is removed from the added lines before any pattern is matched. The slug
# comes from REPO_SLUG, the same origin-derived identity the internal-repo
# exemption above already trusts to skip EVERY pattern, so this grants strictly
# less than that decision does. It is deliberately the smallest narrowing that
# fixes the defect (docs/security/anti-leak.md, "Responding to a finding"):
#
#   * ONE token: the literal `github.com/<REPO_SLUG>`, anchored on the right to
#     a path boundary (`/ " ' backtick whitespace` or end-of-line) so a
#     DIFFERENT repo whose name merely shares this one's prefix is untouched.
#   * A reference to any OTHER repo under the same handle — a PRIVATE repo such
#     as `github.com/nfsarch33/cursor-global-kb`, or the bare handle in a
#     comment or config — carries a different slug (or none), is NOT removed,
#     and still trips the handle pattern. That is the genuine-leak case, pinned
#     in tools/deny-pattern-tests.sh next to this one.
#   * Nothing but this exact public slug is removed. On its own that is NOT
#     enough to make the removal safe — see the v18811 note directly below,
#     which is what makes it safe.
#
# With no github.com origin REPO_SLUG is empty, there is nothing public by
# construction to neutralize, and the diff is scanned unchanged.
#
# v18811 — the seventh, and the only one this file inflicted on itself: v18797
# above introduced a FALSE NEGATIVE, the class this gate exists to prevent.
#
# v18797 removed the own slug from every added line and then matched EVERY
# pattern against the shortened text. Removing text cannot create a match, but
# it can DESTROY one: any pattern whose match had to extend past the slug went
# silent while the payload stayed in the tree verbatim. Reproduced 2026-09-03
# against the merged scanner, in BOTH public repos, using the PUBLIC set only,
# so it needed no secret and no estate identifier:
#
#   +authorized_key: ssh-rsa AAAA<key> runner@github.com/<owner>/<this-repo>
#
# Both SSH-key patterns end `[^@]+@[^@]+`. That trailing `[^@]+` was satisfied
# by the module path and by nothing else on the line, so deleting the path took
# the match with it: exit 0, "OK: no deny-pattern matches". The identical line
# ending `runner@buildhost` exits 1. The Slack-token pattern fails the same way
# (`xoxb-` immediately followed by the module path at end of line).
#
# Two changes. The first is the one that matters:
#
#   1. NEUTRALIZE PER PATTERN, NOT GLOBALLY. A pattern reads the neutralized
#      copy only if the module path is a string that pattern would itself
#      match; every other pattern reads the added lines EXACTLY as written. The
#      false positive v18797 existed to fix is by definition such a pattern —
#      the operator handle IS the owner segment — so none of that fix is lost,
#      while a credential format, an address range or a vendor token, none of
#      which match a module path, can no longer be silenced by the removal.
#      What remains suppressible is only what the public-by-construction string
#      trips on its own, which is exactly the case this was written for.
#
#   2. THE REMOVAL LEAVES A SEPARATOR. Both rules now replace the slug with a
#      single space rather than one of them deleting it outright, so a removal
#      can neither splice its neighbours together nor truncate a line to end
#      one character short of a pattern. This is defence in depth behind (1),
#      never a substitute for it: a space satisfies `[^@]+` but not
#      `[0-9a-zA-Z-]+`, so a separator alone would have fixed the SSH case and
#      left the Slack one open.
#
#   3. AN ENTRY CARRYING AN ALTERNATION IS NEVER NEUTRALIZED. An ERE is not one
#      matcher: a top-level `|` makes it several independent ones, and gating
#      the whole ENTRY on the fact that ONE branch matches the module path puts
#      every OTHER branch on the shortened text — the same defect, reappearing
#      inside a single entry. Measured 2026-09-04 on this scanner with the two
#      regexes `<handle>` and `<token-format>`: as two entries the payload
#      exits 1, combined into one entry it exits 0. Deciding which `|` is
#      top-level needs a regex parser, so the test is the dumber and strictly
#      safer one — ANY `|` in the pattern disqualifies the entry, which can
#      only ever neutralize LESS, never more. The cost is a false positive if
#      someone writes the handle as one branch of an alternation; that is the
#      cheap direction, and pattern_reads_neutralized() below says so.
#
#   4. THE REMOVAL IS CASE-INSENSITIVE, like the matcher. Patterns are matched
#      with `grep -iE`, so an entry can be gated ON by a case-insensitive match
#      and then have the removal miss, because a host name is written
#      `GitHub.com` in prose and a clone URL need not carry the canonical case.
#      Both `s###` commands take the `I` flag (GNU sed; the runners are
#      `[self-hosted, linux]`). This is not a widening in the false-negative
#      direction: only a pattern that itself matches the module path ever reads
#      the neutralized copy, and that pattern is matched case-insensitively
#      anyway, so the removal now agrees with the matcher instead of quietly
#      disagreeing with it.
#
# Pinned in tools/deny-pattern-tests.sh, "DEFECT 6 (v18811)", for both public
# slugs and in both directions.
SCAN_DIFF="$DIFF"
OWN_MODULE_PATH=""
if [[ -n "$REPO_SLUG" ]]; then
  OWN_MODULE_PATH="github.com/$REPO_SLUG"
  # Escape the one ERE metacharacter a GitHub owner/repo slug can carry (`.`)
  # so a literal dot in a repo name cannot widen the removal.
  SLUG_RE="${REPO_SLUG//./\\.}"
  SCAN_DIFF="$(printf '%s\n' "$DIFF" \
    | sed -E "s#github\\.com/${SLUG_RE}([/\"'\`[:space:]])# \\1#gI; s#github\\.com/${SLUG_RE}\$# #gI")"
  # The two copies must stay line-for-line aligned: a MATCH block below is
  # located in SCAN_DIFF and then REPORTED from DIFF by line number, and a
  # misattributed line is precisely this file's recurring failure — a gate
  # saying something other than what it read. sed cannot change the line count
  # here, but a future edit could, so this is checked rather than assumed.
  if [[ "$(printf '%s\n' "$DIFF" | wc -l)" != "$(printf '%s\n' "$SCAN_DIFF" | wc -l)" ]]; then
    echo "ERROR: the neutralized copy is not line-for-line aligned with the" >&2
    echo "       diff, so a reported line number would name the wrong line." >&2
    echo "       Refusing to scan rather than report the wrong evidence." >&2
    exit 2
  fi
fi

# v18811 - the one place that decides whether a pattern reads the neutralized
# copy instead of the added lines as written. Three conditions, all necessary:
#
#   * there is a module path to neutralize at all;
#   * the pattern carries no `|` (see note 3 above — an alternation is several
#     matchers and must never be gated as one); and
#   * the module path, on its own, is a string this pattern matches. If it is
#     not, removing that path cannot change this pattern's verdict, so the
#     pattern reads the diff exactly as written.
#
# Deliberately NOT tested: the module path embedded in surrounding context. A
# pattern that only matches once the path has a trailing `/` or an adjacent
# character is classified here as not-gated, so v18797's false positive returns
# for that pattern alone. That is the cheap direction and it is recorded in
# docs/security/anti-leak.md; widening this test would suppress MORE, which is
# the direction that costs false negatives.
pattern_reads_neutralized() { # $1 = pattern
  [[ -n "$OWN_MODULE_PATH" ]] || return 1
  case "$1" in *"|"*) return 1 ;; esac
  printf '%s\n' "$OWN_MODULE_PATH" | grep -qiE -- "$1"
}

# PUBLIC deny patterns (case-insensitive extended regex).
# Format: PATTERN|LABEL (for human-readable output)
#
# Vendor credential FORMATS and the generic private-address ranges only. None
# of these names this estate, so this array is safe in a public tree — which
# matters, because this file is installed into public repositories. Anything
# that identifies the estate belongs in the internal set loaded below, NOT
# here. See the v18793 note at the top before adding a pattern.
PATTERNS=(
  'api[.]minimax[.]io|minimax.io domain (must use api.minimaxi.com)'
  'sk_live_|Stripe live key prefix'
  'AKIA[0-9A-Z]{16}|AWS access key ID'
  'ghp_[A-Za-z0-9]{36}|GitHub personal access token'
  'github_pat_[A-Za-z0-9_]{82}|GitHub fine-grained PAT'
  'xox[baprs]-[0-9a-zA-Z-]+|Slack token'
  'ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3} ?[^@]+@[^@]+|SSH RSA public key (use ed25519)'
  'ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3} ?[^@]+@[^@]+|SSH ed25519 public key'
  '100\.[0-9]+\.[0-9]+\.[0-9]+|Tailscale IP (internal)'
  '10\.[0-9]+\.[0-9]+\.[0-9]+|RFC1918 internal IP'
  '192[.]168[.][0-9]+\.[0-9]+|RFC1918 internal IP'
  '172[.](1[6-9]|2[0-9]|3[01])[.][0-9]+\.[0-9]+|RFC1918 internal IP'
)
PUBLIC_COUNT="${#PATTERNS[@]}"

# INTERNAL deny patterns, appended at runtime from a file this repository does
# not ship. Same PATTERN|LABEL format, one per line; blank lines and lines
# starting with # are ignored.
#
# The three states are deliberately distinguishable, because the failure this
# scanner keeps having is a run that reports something other than what it did:
#
#   unset                  -> public set only, said out loud on every run.
#                             A real reduction in coverage, announced.
#   set and readable       -> both sets, with the counts printed (never the
#                             patterns themselves — this output reaches public
#                             CI logs).
#   set but not readable,  -> exit 2. It was configured and did not load, and
#   or carrying no usable     that must never be mistaken for "not configured".
#   patterns
INTERNAL_PATTERNS_FILE="${HLXN_DENY_PATTERNS_FILE:-}"
INTERNAL_COUNT=0
if [[ -n "$INTERNAL_PATTERNS_FILE" ]]; then
  if [[ ! -r "$INTERNAL_PATTERNS_FILE" ]]; then
    echo "ERROR: HLXN_DENY_PATTERNS_FILE is set to '$INTERNAL_PATTERNS_FILE'," >&2
    echo "       but that file is not readable. The internal pattern set was" >&2
    echo "       NOT loaded, so nothing that identifies this estate was" >&2
    echo "       checked. Fix the path, or unset the variable to scan with" >&2
    echo "       the public set only." >&2
    exit 2
  fi
  # `|| [[ -n "$line" ]]`: a final line with no trailing newline still counts.
  # tr -d '\r' equivalent inline, for a file that came through a CRLF path.
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" ]] && continue
    [[ "$line" == \#* ]] && continue
    # A line with no | has no label and would silently become a pattern whose
    # label is itself. Skip it rather than guess.
    [[ "$line" == *"|"* ]] || continue
    PATTERNS+=("$line")
    INTERNAL_COUNT=$((INTERNAL_COUNT + 1))
  done <"$INTERNAL_PATTERNS_FILE"
  if [[ "$INTERNAL_COUNT" -eq 0 ]]; then
    echo "ERROR: HLXN_DENY_PATTERNS_FILE '$INTERNAL_PATTERNS_FILE' contained no" >&2
    echo "       usable PATTERN|LABEL lines. Refusing to report a pass on a" >&2
    echo "       set that was configured and did not load." >&2
    exit 2
  fi
fi

# Counts, never the patterns. This line is the coverage statement for the run.
if [[ "$INTERNAL_COUNT" -gt 0 ]]; then
  echo "Patterns: $PUBLIC_COUNT public + $INTERNAL_COUNT internal (from HLXN_DENY_PATTERNS_FILE)"
else
  echo "Patterns: $PUBLIC_COUNT public only - the internal set is NOT loaded (HLXN_DENY_PATTERNS_FILE unset)."
  echo "          Estate identifiers (vault and token names, operator addresses,"
  echo "          host naming) are NOT checked in this run. See docs/security/anti-leak.md."
fi

# MATCHED counts the PATTERNS that matched, which is exactly the number of
# "MATCH [...]" blocks printed below. It was a 0/1 flag that the summary then
# printed as if it were a count, so every failing run ended with "FAIL: 1
# pattern match(es)" however many blocks it had just printed above that line.
# v18809 - every pattern must compile before any of them runs.
#
# An entry is pattern|label, and the PATTERN is everything before the LAST
# delimiter, not everything before the first. It used to be `${entry%%|*}`,
# which truncates at the first `|` INSIDE the pattern: the RFC1918 172.16/12
# entry carries an alternation, so this loop compiled `172[.](1[6-9]`, grep
# exited 2 on the unmatched parenthesis, the `2>/dev/null || true` below
# swallowed the error, and that entry matched nothing for as long as it
# existed. A dead pattern and a clean diff print the same line, which is why
# the compile check is not optional: an entry grep cannot parse is an
# infrastructure failure, never a clean scan.
for entry in "${PATTERNS[@]}"; do
  PROBE="${entry%|*}"
  # `|| PROBE_RC=$?` matters: this script runs under `set -e`, and grep exits 1
  # on the empty input whenever the pattern is merely valid. Only 2 and above
  # mean grep could not parse it.
  PROBE_RC=0
  grep -qE -- "$PROBE" /dev/null || PROBE_RC=$?
  if [[ "$PROBE_RC" -ge 2 ]]; then
    echo "ERROR: deny pattern does not compile: ${entry##*|}" >&2
    echo "       A pattern grep cannot parse reports nothing, which reads as clean." >&2
    exit 2
  fi
done

# v18811 - which patterns the own-module-path neutralization actually applies
# to, said out loud before the scan rather than left to be inferred. Only a
# pattern the module path itself matches can be suppressed by removing that
# path; for every other pattern the neutralized copy is not consulted at all.
# The count is printed, never the labels: this output reaches public CI logs.
NEUTRALIZED_FOR=0
if [[ -n "$OWN_MODULE_PATH" ]]; then
  for entry in "${PATTERNS[@]}"; do
    if pattern_reads_neutralized "${entry%|*}"; then
      NEUTRALIZED_FOR=$((NEUTRALIZED_FOR + 1))
    fi
  done
  echo "Neutralizing this repo's own public module path github.com/$REPO_SLUG for $NEUTRALIZED_FOR of ${#PATTERNS[@]} pattern(s) - the ones that string trips by itself (public by construction; see docs/security/anti-leak.md)"
fi

MATCHED=0
for entry in "${PATTERNS[@]}"; do
  PATTERN="${entry%|*}"
  LABEL="${entry##*|}"
  # v18811 - the subject is the added lines EXACTLY as written, UNLESS this is
  # a pattern the repo's own module path would itself match, in which case it
  # is the neutralized copy. Matching every pattern against the shortened text
  # is how v18797's removal became a false negative; see the note above.
  SUBJECT="$DIFF"
  if pattern_reads_neutralized "$PATTERN"; then
    SUBJECT="$SCAN_DIFF"
  fi
  # Use grep -iE with -- to delimit. Located in SUBJECT, but REPORTED from DIFF
  # below: for a neutralized pattern the subject line has had the module path
  # replaced by whitespace, and printing that as the finding quoted an
  # offending line that existed in no file — so `grep -F` on the evidence found
  # nothing and the column offsets were wrong. The two copies are line-for-line
  # aligned (asserted where SCAN_DIFF is built), so the line number transfers.
  MATCH_LINES=$(printf '%s\n' "$SUBJECT" | grep -niE -- "$PATTERN" 2>/dev/null \
                | cut -d: -f1 || true)
  if [[ -n "$MATCH_LINES" ]]; then
    # tr -d: `wc -l` pads its count on some platforms, and the arithmetic
    # below needs a bare integer.
    LINES="$(printf '%s\n' "$MATCH_LINES" | wc -l | tr -d '[:space:]')"
    echo ""
    echo "MATCH [$LABEL] ($LINES matching line(s)):"
    printf '%s\n' "$MATCH_LINES" | head -3 | while read -r n; do
      printf '%s\n' "$DIFF" | sed -n "${n}p"
    done | sed 's/^/  /'
    # The block is capped at three lines. Say what was hidden, for the same
    # reason the summary must not undercount: a gate that shows less than it
    # found reads as a smaller problem than it is.
    if [[ "$LINES" -gt 3 ]]; then
      echo "  ... and $((LINES - 3)) more matching line(s) not shown"
    fi
    MATCHED=$((MATCHED + 1))
  fi
done

if [[ "$MATCHED" -gt 0 ]]; then
  echo ""
  echo "FAIL: $MATCHED deny pattern(s) matched in diff against $BASE_REF"
  echo "      See docs/security/anti-leak.md and L0 rule 01-public-repo-sanity.mdc"
  echo "      Remove the offending content and amend the commit before pushing."
  exit 1
fi

echo "OK: no deny-pattern matches in diff against $BASE_REF"
exit 0
