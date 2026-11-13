# prox

Transparent TLS logging proxy for Linux. prox sits between a client device
and its upstream using TPROXY: it intercepts selected TCP ports, attempts a
MITM (per-host forged leaf certs signed by an operator-supplied
intermediate), and captures both directions to per-connection directories
under the data root. Where MITM is not possible it degrades to a plain
transparent relay (raw passthrough). Every capture carries build
provenance: the git commit that wrote it.

## Build

`make` builds `./prox` and stamps the git commit into the binary
(`pkg/version.Commit` via ldflags). An unstamped binary (empty or `dev`
commit) refuses to start, and `make` refuses to build without a resolvable
commit, so every capture names the build that wrote it.

## Gates

Keep all four green on every change:

- `gofmt -l .` — no output
- `go vet ./...`
- `go test -count=1 ./...`
- `cd example/hooks && go build ./...`

## Package layout

- `pkg/prox` — facade: config, lifecycle (`New`/`Register`/`Run`/`Shutdown`),
  TPROXY listener, rule lifecycle; embeds the data model guide installed at
  the data root on startup.
- `pkg/proxy` — relay ladder: plain-HTTP, TLS (MITM), and raw passthrough
  serving; serve-mode decisions.
- `pkg/hooks` — consumer hook API: `Pipeline`, per-connection `Pipe`,
  per-direction filtered writers, hold/serve/label/event extensions.
- `pkg/capture` — per-connection stream API (bounded pull, post-decision
  chunk records, `CloseInfo`); the in-process mirror of the on-disk record.
- `pkg/config` — YAML config, defaults, validation.
- `pkg/rules` — TPROXY iptables / ip-rule computation.
- `pkg/sink` — file sink: per-connection directories under the data root.
- `pkg/sniff` — protocol sniffing (TLS ClientHello parsing).
- `pkg/store` — SQLite patched-pair store.
- `pkg/tlsutil` — CA/leaf handling, minting, chain building, SCT.
- `pkg/isolation` — built-in client–upstream isolation hook.
- `pkg/chanpipe` — in-memory duplex `net.Conn` for hermetic tests.
- `pkg/version` — build stamp.
- `example/hooks/` — working hook consumer (separate module).

## Constraints

- Go 1.27; Linux only (TPROXY, iptables, raw syscalls).
- Zero per-connection goroutines in the relay path; bounded capture per
  direction (default 256 MiB).
- Tests are hermetic: no network, temp-dir filesystem only.
- The operator supplies the intermediate CA and key; never commit CA
  material. Operate only on networks you own.

## Publishing

The public packaging branch is the orphan `publish` (single squashed commit,
tag `v0.1.0`), held in the worktree `.worktrees/publish` — that tree is what
gets pushed (as `main` + the tag) to `github.com/nicois/prox`. Local `main`
keeps the full private history; tag `pre-publish` marks the join point. When
`main` moves, rebuild the orphan from main's tree object (`git commit-tree
main^{tree}` + `git update-ref refs/heads/publish`, re-point `v0.1.0`) and
verify with a **content** diff — `git diff main..publish` must be empty. Never
re-stage from the worktree's on-disk content (it silently ships a stale tree).
Rebuild history and deployment status: `AGENTS.local.md` (local-only).

## Pointers

- Design + config reference:
  `docs/superpowers/specs/2026-11-02-transparent-tls-proxy-design.md`
- Data model (installed at `<dataroot>/AGENTS.md` at runtime):
  `pkg/prox/datamodel.md`
- Example hook consumer: `example/hooks/`
