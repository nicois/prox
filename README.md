# prox — transparent TLS logging proxy

prox is a transparent TLS logging proxy for Linux. It intercepts TCP traffic
passing through a host with TPROXY/iptables, terminates TLS with forged
per-host leaf certificates (fresh leaf keypairs signed by an operator-supplied
intermediate CA) and captures the decrypted application bytes per connection.
Where MITM is not possible — a client that rejects the forged chain, an mTLS
upstream, or traffic that is not TLS at all — it degrades to a plain
transparent relay of the verbatim bytes, so nothing is lost, only undecrypted.

Every proxied connection gets its own directory under a data root with the
client→server and server→client byte streams plus a JSON event log. A host Go
application can extend the relay with the hook API — observe, modify, hold, or
block bytes and connections — without touching the proxy's source. A
built-in client–upstream isolation mode captures traffic without delivering it
to the client at all.

## Requirements

- Linux with TPROXY and iptables support (the mangle rules are applied at
  startup and removed at shutdown).
- Root: `CAP_NET_ADMIN` for the TPROXY rules, and read access to the CA key
  file (default mode `0600`).
- Go 1.27.3 or newer (latest 1.27 patch) to build — stdlib CVE fixes, incl. GO-2026-6809 (x509 eMudhra distrust), landed in 1.27.3; earlier 1.27.x releases carry reachable stdlib advisories.

## Build

```
make
```

`make` stamps the git commit into the binary (`-X github.com/nicois/prox/pkg/version.Commit`).
The stamp lands in the `meta` event at the head of every captured stream and in
the startup journal line, so each capture is traceable to the build that wrote
it. Unstamped builds (e.g. a plain `go build` bypassing the Makefile) refuse to
start at runtime.

## Quick start

1. Build with `make`, then install the binary and a config file:

   ```
   install -m 755 prox /usr/local/bin/prox
   install -d -m 750 /etc/prox
   # place your intermediate CA cert/key (+ optional chain) and config in /etc/prox/
   ```

   A fully worked reference config — including the incident CA material in
   [`deploy/emudhra/`](deploy/emudhra/) — is at
   [`deploy/emudhra/config.yaml`](deploy/emudhra/config.yaml).

2. Make the proxy host the client's gateway (forwarding, NAT, ARP pinning):

   ```
   sudo GW_ADDR=<this-hosts-lan-ip> CLIENT_NET=<client-subnet> ./deploy/setup-gateway.sh
   ```

3. Install the TPROXY rules (idempotent; `--dry-run` / `--remove` supported):

   ```
   sudo ./deploy/tproxy-setup.sh
   ```

4. Install and start the unit:

   ```
   install -m 644 deploy/prox.service /etc/systemd/system/prox.service
   systemctl daemon-reload
   systemctl enable --now prox
   journalctl -u prox -f          # structured JSON operator events
   ```

   The unit runs `/usr/local/bin/prox -config /etc/prox/config.yaml`; capture
   goes to `/var/lib/prox` (`StateDirectory`), not to the journal.

5. Verify from a client whose traffic is intercepted (needs only curl and
   openssl): `./deploy/smoke.sh -c /path/to/intermediate.pem -u upstream -p port`.

The full configuration reference is section 9 of the design spec:
[`docs/superpowers/specs/2026-11-02-transparent-tls-proxy-design.md`](docs/superpowers/specs/2026-11-02-transparent-tls-proxy-design.md).

## Configuration

YAML file (path via `-config`; built-in defaults when the flag is empty or the
file is missing) plus command-line overrides: `-listen` overrides the listen
address, `-log-level` sets the journal level (`debug`, `info`, `warn`,
`error`).

| key | default | meaning |
|---|---|---|
| `listen` | `0.0.0.0:31280` | TPROXY on-port the listener binds |
| `ports` | `[80, 443]` | destination ports captured |
| `dataroot` | `/var/lib/prox` | per-connection capture root |
| `ca[]` | `[]` | compromised intermediates, round-robin: `cert_pem`, `key_pem`, optional `chain_pem` (extra CERTIFICATE blocks served after the intermediate — for clients whose trust store lacks the intermediate's issuer) |
| `mitm.validity_days` | `7` | leaf validity window, ±N days around now |
| `mitm.ct_log_url` | *(unset)* | CT log `addchain` endpoint; when set, each fresh leaf is re-issued with the log's SCT embedded before it is served |
| `mitm.patched_recheck` | `720h` | interval at which patched (ip, host) pairs are re-tried for MITM |
| `mitm.tunnel_fallback` | `false` | patched-pair fallback: `false` (default) drops a patched pair's connection and logs the stored rejection reason (`result=patched_drop`); `true` serves it with the legacy pass-through tunnel, which propagates both TLS negotiations verbatim (recovery for a pinned device, not a capture) |
| `mitm.upstream_cas` | `[]` | extra PEM files trusted when verifying the upstream (real server) leg, for upstreams presenting certs no system store trusts |
| `log.per_conn_max_bytes` | `268435456` (256 MiB) | per-direction capture cap per connection (bounds the `.bin` capture bytes only; `meta.jsonl` keeps being journaled) |
| `log.retention_max_age` | `90d` | day-dirs older than this are deleted (daily sweep) |
| `log.retention_max_size` | `214748364800` (200 GiB) | oldest day-dirs are deleted beyond this total |
| `log.file_mode` | `0600` | permission of capture files at creation time (unquoted octal; existing files are not re-chmodded) |
| `log.dir_mode` | `0700` | permission of capture directories at creation time (unquoted octal; existing directories are not re-chmodded) |
| `rules.mode` | `managed` | TPROXY rule ownership: `managed` (default) — prox installs the rules at startup (clearing stale state first) and removes them at shutdown; `consumer` — prox assumes the operator or embedding host has already diverted the traffic (TPROXY to the listen address with the configured fwmark/routing) and installs and removes nothing, including on exit |
| `rules.fwmark` | `1` | socket mark set on captured traffic |
| `rules.routing_table` | `100` | local routing table for the TPROXY return-path correction |
| `rules.ifaces` | `[]` (all) | capture only traffic arriving on these interfaces (container traffic arrives on bridge veth ports and is excluded) |
| `isolation` | `off` | client–upstream isolation mode: `off` (normal relay), `full` (capture c2s, no upstream connection, nothing delivered to the client), `readonly` (c2s is mirrored to the real upstream, s2c is captured but not delivered to the client) |
| `s2c_max_packet` | `0` (disabled) | cap on the size of s2c chunks forwarded to the client, in chunk units (one upstream read delivery — one TLS record on a MITM leg). All-or-nothing: an oversized chunk is dropped whole and within-cap chunks are forwarded byte-exact. Dropped chunks are still captured (the capture is the complete wire) and each drop is logged as an `s2c_drop` event with `start`/`end` offsets into the captured `s2c.bin`. No effect under `full` or `readonly` isolation. Consequence: a dropped middle record corrupts the client's application stream; the client typically resets at the next record |

`listen`, `ports`, and `rules` must match the iptables rules in
`deploy/tproxy-setup.sh` — the binary re-applies the rules from these values at
startup and removes them at shutdown. That is `managed` mode (the default). In
`consumer` mode (`rules.mode: consumer`) prox assumes the operator or embedding
host has already diverted the traffic (TPROXY to the listen address with the
configured fwmark/routing) and installs and removes nothing — including on
exit. For the library surface, `Prox.SetRulesRunner(rules.Runner)` (call
before `Run`) substitutes the runner the managed-mode rule lifecycle uses for
the iptables/ip commands; `nil` (the default) is the built-in exec runner, and
in `consumer` mode it is never called.

## Data model

The binary installs a data-model guide at `<dataroot>/AGENTS.md` on every
startup (reinstalling it each start — do not edit it by hand). It documents the
per-connection layout (`conns/<YYYYMMDD>/<connid>/` with `meta.jsonl`,
`c2s.bin`, `s2c.bin`), what the `.bin` files contain per connection kind
(decrypted bytes for MITM, cleartext HTTP for plain, verbatim wire bytes for
raw), the `meta.jsonl` event vocabulary, and the `index.db` patched-pair
schema. The source of the embedded guide is
[`pkg/prox/datamodel.md`](pkg/prox/datamodel.md).

In-process hosts do not need the files: the same record is available as an API
via `pkg/capture` — a per-connection stream of chunk records (forwarded,
dropped, and injected bytes with reasons), TLS outcome, close info, and flow
labels. Chunk payloads are opt-in: records carry no bytes until
`Registry.EnableBytes()` is called on the registry.

## Hooks & capture API

`pkg/hooks` gives a host Go application per-connection decision points into the
relay: passively observe the byte streams, modify them, or block a connection
or individual chunks, in either direction. A hook implements `Filter` (a
`Match` on src/dst/dport selecting the connections it applies to) and
`OnOpen`/`OnData`/`OnClose`; a `Result` replaces, drops, or closes. `OnOpen`
receives a `HookConn` the hook can write through on its own initiative (e.g.
manufacture server messages while the real upstream's are blocked). Phase-2
surfaces: `Serving` decides per flow at establishment how it is served (mirror
/ tunnel / local / reject); `Result.Hold` buffers a chunk in a bounded
per-direction hold buffer (default 16 MiB, backpressuring only the holding
direction) released via `HookConn`; labels set on the `Conn` ride onto the
capture record; `EventObserver` receives typed lifecycle and pressure events
in-band; `TLSObserver` receives the client-leg TLS outcome. A `Pipeline`
registers hooks (safe while the proxy is running). Hook calls are synchronous
and unbounded: a hook that blocks pins that connection.

[`example/hooks/`](example/hooks/) is a standalone consumer module (two hooks:
a passive connection logger and an active byte redactor) — build it and run it
instead of the stock binary to see the API in use. `pkg/capture` is the
stream/record side: `NewStream` builds the per-connection record (bounded
in-memory chunk ring, default 100k chunks) and a `Registry` collects finished
streams for consumers.

Chunk records carry metadata only (`Len`, decision, `Reason`/`Origin`) unless
payload capture is opted in: `Registry.EnableBytes()` turns it on for streams
opened after the call (default off — records carry no `Payload` and the record
path pays only a bool check). When on, a record's `Payload` is a copy of the
chunk's bytes at the record site — the forwarded bytes for `Forwarded`, the
chunk as the dropping hook received it for `Dropped`, the held bytes for held
paths, the bytes actually written for `Injected`, the dropped bytes for the
s2c cap — safe to retain. Retention is bounded by the same chunk ring as the
records (`SetMaxChunks`).

Write-order contract: writes to a direction (the relay's own, hook-injected,
and held releases) serialize under the per-direction lock — each write is
chunk-atomic, so a direction's bytes arrive in FIFO write order. There is no
total order between injected and relayed bytes: the record sequence is not the
wire order across sources, so join hook activity on the record identity it
carries (`Origin`/`Decision`/`Reason`), never on stream position. The s2c cap
is the one decision path with no hook verdict: an over-cap s2c chunk records
`Dropped` with reason `s2c_max_packet` (plus the `s2c_drop` sink event).

## Security

- **Operate only on networks you own.** This is an interception tool; running
  it on traffic you do not own is illegal in most jurisdictions.
- MITM requires an intermediate CA the client trusts.
  [`deploy/emudhra/`](deploy/emudhra/README.md) contains the public eMudhra
  weak-key incident material (CVE-2026-111943): a publicly recoverable
  intermediate key, the chain, and a worked config. Browsers and OSes revoked
  the affected certificates; see `deploy/emudhra/README.md` for what still
  works and what does not.
- Captured `tls` connections are **decrypted application bytes**. Capture
  files default to `0600` and directories to `0700` at creation; loosen via
  `log.file_mode`/`log.dir_mode` deliberately (creation-time only).
- Known v1 limitations:
  - The per-host forged-leaf cache is unbounded and CT submission is
    synchronous: a flood of connections with distinct SNIs grows the cache and
    stalls goroutines on CT-log calls (memory/connection exhaustion). Planned
    post-v1.
  - `index.db` is created world-readable (`0644`) by the sqlite driver; it
    holds only the patched (ip, host) pairs, not traffic.
  - Past the per-direction `per_conn_max_bytes` capture cap, `s2c_drop`
    `start`/`end` offsets refer to the truncated file, not the full stream.

## License

[Apache License 2.0](LICENSE) — see [LICENSE](LICENSE) for the full text.
