# telepath-core — project notes for Claude Code

This file is a run-book for building, testing, and releasing **telepath-core**.
Treat the rules here as non-optional unless `../telepath-v2/docs/ARCHITECTURE.md`
or the operator overrides them.

## What this repo is

Go daemon + CLI + MCP stdio adapter — a single binary dispatched by subcommand —
that backs FSC's telepath Claude Code plugin. v0.1 scope is in
`../telepath-v2/docs/PRD.md` §11 (weeks 1–7 shipped).

- `cmd/telepath/` — cobra CLI entry point
- `internal/` — daemon, ipc, engagement, audit, keys, roe, vault, findings,
  notes, rendering, export, proxy/{sshproxy,httpproxy}, transport, hooks,
  config
- `pkg/schema/` — wire-format types shared with the plugin's Python hook lib
- `scripts/` — `build-release.sh` (local), `smoke-test.sh`, `nfpm.yaml`
- `.github/workflows/` — `ci.yml` + `release.yml`

## Build & test

```sh
go build -o bin/telepath ./cmd/telepath         # local build
go test ./...                                    # unit tests (cached)
go test -race -count=1 ./...                     # race detector
go vet ./...                                     # linting
bash scripts/smoke-test.sh                        # end-to-end (builds bin/ first)
```

CI on every push runs all four on `ubuntu-latest`, plus a cross-compile check
matrix for darwin/arm64, darwin/amd64, windows/amd64, linux/arm64.

## Commit message convention (required)

We use **Conventional Commits**. `git-cliff` reads these prefixes to build
release notes automatically — **no hand-written notes**, so every commit
message is effectively a release-notes line for the next tag.

| Prefix       | Meaning                             | Release-notes section |
|--------------|-------------------------------------|-----------------------|
| `feat:`      | new feature                         | Features              |
| `fix:`       | bug fix                             | Bug Fixes             |
| `perf:`      | performance change                  | Performance           |
| `docs:`      | docs only                           | Documentation         |
| `refactor:`  | non-functional code change          | Refactoring           |
| `test:`      | tests only                          | Testing               |
| `ci:`        | CI/workflow changes                 | Build & CI            |
| `build:`     | build-system/dep changes            | Build & CI            |
| `chore:`     | misc housekeeping                   | Chores                |
| `security:`  | security-relevant change            | Security              |
| `revert:`    | reverting a previous commit         | Reverts               |

Breaking changes use `!`: `feat!: drop v0.1 engagement.yaml format`
or a `BREAKING CHANGE:` footer.

Optional scope in parentheses: `feat(vault): ...`, `fix(sshproxy): ...`.

Multi-line commits: subject is the first line (≤72 chars) and it's what
shows up in notes; body is free-form.

## Release workflow — the standardized procedure

Releases are **tag-triggered**. Nothing human-written gets posted to the
Release page — body, assets, signatures, SBOMs all flow from the workflow.

### To cut release vX.Y.Z

1. Make sure `main` is green (CI status on latest commit == success).
   - `gh run list --repo JongoDB/telepath-core --workflow=ci --limit 1`
2. All commits since the previous tag follow the convention above. If any
   don't, either:
   - amend / squash / rewrite before tagging, **or**
   - accept that those commits go under "Other" in the notes.
3. Tag & push:
   ```sh
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
4. Watch `.github/workflows/release.yml`:
   ```sh
   gh run watch --repo JongoDB/telepath-core $(gh run list --repo JongoDB/telepath-core --workflow=release --limit 1 --json databaseId --jq '.[0].databaseId')
   ```

### What the release workflow produces

For a single tag push, all of this happens automatically:

- **Build matrix (5 runners)**:
  - `ubuntu-latest` → linux/amd64 (+ `.deb` + `.rpm` via nfpm)
  - `ubuntu-latest` → linux/arm64
  - `macos-latest` → darwin/arm64 (Apple Silicon)
  - `macos-latest` → darwin/amd64 (Intel Mac — cross-compiled with CGO=0)
  - `windows-latest` → windows/amd64
- **SBOM** (`syft`, CycloneDX JSON) per binary → attached to the release
- **Direct upload** of every artifact to the GitHub Release via
  `softprops/action-gh-release@v2` (bypasses the org's Actions-artifact
  storage quota — Release assets use a separate, much larger bucket)
- **Finalize job** (runs after the matrix):
  - `git-cliff --latest` generates the Release body from the commits since
    the previous tag, using `cliff.toml`
  - `SHA256SUMS` computed over every release asset
  - `cosign sign-blob --yes SHA256SUMS` signs keyless via GitHub OIDC →
    Fulcio/Rekor; produces `SHA256SUMS.sig` + `SHA256SUMS.crt`
  - `SHA256SUMS` + signature + cert attached; Release body set from git-cliff

A complete release page has 15 assets:

- 5 binary archives (4 `.tar.gz` + 1 `.zip`)
- 5 `.sbom.json`
- 1 `.deb` + 1 `.rpm`
- `SHA256SUMS` + `SHA256SUMS.sig` + `SHA256SUMS.crt`

### How operators install

Two paths, both documented in the Release body's **Quick install** block:

1. **One-liner** (macOS + Linux):
   ```sh
   curl -sSL https://raw.githubusercontent.com/JongoDB/telepath-core/main/scripts/install.sh | sh
   ```
   `scripts/install.sh` probes `uname -s` / `uname -m`, resolves the latest
   tag via the GitHub Releases API, downloads the matching tarball,
   extracts it to a temp dir, and `exec`s `./telepath install`.
   `VERSION=vX.Y.Z` pins an explicit tag.
2. **Manual**: download the platform-specific `.tar.gz` (or `.zip` on
   Windows) from the Release page, extract, run `./telepath install`.

`telepath install` copies the running binary to `~/.local/bin/telepath`
(Unix) or `%LOCALAPPDATA%\telepath\bin\telepath.exe` (Windows), detects if
the target dir is already on PATH, and prints the shell-specific export
line only when needed.

### If a release run fails mid-flight

A partial release is OK — artifacts are idempotent: re-running the workflow
will re-upload the same files (softprops overwrite-on-conflict). If you need
a clean slate:

```sh
gh run cancel <run-id> --repo JongoDB/telepath-core
gh release delete vX.Y.Z --repo JongoDB/telepath-core --yes --cleanup-tag
git tag -d vX.Y.Z
git push origin :refs/tags/vX.Y.Z
# fix whatever, commit, push
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

## Operational invariants (do not regress)

Tests catch most of these; some are caught by the smoke test. All are
documented in `../telepath-v2/docs/ARCHITECTURE.md`.

- **Audit log is append-only + hash-chained + Ed25519-checkpointed.** Never
  mutate or truncate `audit.jsonl`. Breaks of the chain are what make the
  bundle defensible.
- **ROE evaluation order**: out-of-scope > in-scope > protocol allow-list >
  blackout window. Changing this ordering is a scope-bypass bug magnet.
- **Scope enforcement is server-side.** Plugin/hook/CLI helpers cannot
  weaken this — classifier changes must never convert a historical "write"
  into "read-only pass-through."
- **Credentials never appear in audit payloads.** Use
  `hooks.RedactCredentials` or the credential vault's reference IDs.
- **CGO stays disabled in release builds.** `zalando/go-keyring` shells out
  to `/usr/bin/security` on macOS (no CGO needed). New deps should preserve
  this so cross-compile from Linux keeps working.
- **Engagement ID is a path component.** Validated against a strict regex
  in `internal/engagement/manager.go`. Don't loosen it.
- **Hook protocol method names are a contract** with the plugin's Python
  hook lib (`hooks/telepath_hook_lib.py`). Rename → break the plugin. Add
  new methods instead.

## Memory pointers (for Claude)

- Memory system at `/home/telepath/.claude/projects/-home-telepath-telepath-v2/memory/`
  tracks user preferences (no mid-stack handoffs, terse reporting, etc.) and
  milestone progress. Load it at session start.
- The plugin repo at `../telepath-v2` is the source of the skills, hooks,
  subagents, commands, and docs; telepath-core is the daemon + CLI half.
  Keep in mind when tests reference `TELEPATH_TEMPLATES_DIR`.
