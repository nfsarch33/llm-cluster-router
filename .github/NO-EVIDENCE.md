# NO-EVIDENCE.md

`llm-cluster-router` is a **public** mirror. The public repo must not contain
runtime evidence, internal topology, or 1Password secrets.

**Rule of thumb**: anything that the operator would not paste in a public
forum does not belong here. Move it to the cursor-global-kb repo (private,
under `evidence/v18750-*/`).

Specifically forbidden:

- 1Password item UUIDs, vault names, or field references (e.g.
  `<vault>/<uuid>`).
- Production hostnames, IP addresses, or jump-server names (any
  `*.example.com` replacements must keep the structure but use the
  placeholder host).
- `ssh <operator-jump>` commands that target private infrastructure.
- `evidence/` directory contents (must live in cursor-global-kb only).
- LightSail / operator jump-host identities.

If you find a leak, run `bash tools/leak-scan.sh` and resolve before
opening a PR. The CI gate `leak-scan.yml` will fail any PR that introduces
leaks.
