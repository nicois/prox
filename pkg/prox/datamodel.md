# /var/lib/prox — data model

Written by the `prox` transparent proxy.
The binary reinstalls this file at every startup; do not edit it by hand.

> In-process hosts do not need these files: the same record is available as an API via `pkg/capture` (per-connection stream with post-decision chunk records; every decision path records `Len` — a hook drop records the chunk as the dropping hook received it, post earlier-hook transforms). An s2c chunk dropped by the `s2c_max_packet` cap records `Dropped` with reason `s2c_max_packet` on the stream (in addition to the `s2c_drop` event); held bytes released through the cap pass it like any chunk — an over-cap release records `Dropped/s2c_max_packet`, never `Forwarded`). Chunk records carry no payload bytes by default; `Registry.EnableBytes()` (call it before connections open) turns on opt-in capture, after which each record's `Payload` holds a copy of the chunk's bytes at the record site — retention bounded by the same chunk ring as the records. This document describes the on-disk form only.
>
> The record's `CloseInfo` also carries a flow label map and a `serve_mode`. prox's built-in client–upstream isolation (`cfg.Isolation`) marks its flows in that map: a full-isolation flow records `serve_mode: local` + label `isolation=full`, and a read-only flow records label `isolation=readonly`.

## Layout

```
index.db                          # SQLite: patched (ip, host) pairs
conns/<YYYYMMDD>/<connid>/        # connid = <unix-ms>-<seq>, one dir per connection
  meta.jsonl                      # JSON events, one per line, appended over the connection's life
  c2s.bin                         # client -> server bytes, in arrival order
  s2c.bin                         # server -> client bytes, in arrival order
```

## What the .bin files contain

Depends on the `kind` in the connection's `conn_open` event:

- `tls` (MITM succeeded): **decrypted application bytes**. The vendor cloud
  channel (dst `198.51.100.72:14431`) speaks a **binary vendor protocol**, not
  HTTP: `0x7e`-framed messages with device serials embedded as ASCII. Do not
  expect request/response lines here.
- `plain`: cleartext HTTP bytes.
- `raw`: verbatim on-the-wire bytes as relayed. If the traffic was TLS, these
  are **encrypted records** — undecryptable from this data alone.

## meta.jsonl events (as written by the current binary)

`ts` is unix milliseconds on every event. `client` is the original source
(host:port), `dst` the original destination (recovered from the TPROXY socket
tuple). `id` matches the `id` field of the operator journal
(`journalctl -u prox`, structured JSON).

| type | fields |
|---|---|
| `meta` | `ts, commit` — first line of every stream: the prox build (git commit short hash) that wrote it; `dev` for unstamped builds |
| `conn_open` | `ts, id, kind` (`tls`\|`plain`\|`raw`), `client, dst, sni` |
| `leaf_presented` | `ts, cn`, `valid_until` (RFC 3339 UTC), `chain` (comma-joined subject CNs, leaf first), `sct` (bool — the leaf carries an embedded SCT), `sig` (leaf signature algorithm, e.g. `ECDSA-SHA256`) — emitted when a leaf was minted, before the client handshake (so it precedes both the `success` and `client_rejected` results): WHAT the client leg was presented, so a rejection is analyzable from the log alone; the journal counterpart is the `leaf` event (same fields plus `id` and `host`) |
| `mitm_attempt` | `ts, host, dst, result` (`success`\|`client_rejected`\|`mint_failed`\|`mtls`\|`upstream_error`\|`upstream_dial_failed`\|`patched_drop`) — `client_rejected` carries `err` (the client-leg handshake error — the client failed to accept the forged chain) and marks the (ip, host) pair patched, unless `err` is the handshake timeout — a stalled client is not evidence the client rejected the forged chain, so the timeout leaves the pair unmarked; `patched_drop` carries `reason` (the stored rejection reason) — the patched pair's connection was dropped, the default fallback; with `mitm.tunnel_fallback: true` the pair tunnels instead (see `record_summary reason=patched` below) |
| `record_summary` | `ts, reason` (`patched`\|`mtls`\|`upstream_error`\|`tunnel`) — `patched` marks a patched-pair fallback decision: the connection was dropped (default, with the `mitm_attempt patched_drop` event) or tunneled verbatim (`mitm.tunnel_fallback: true` — the client's ClientHello and the server's flight cross the proxy; the `.bin` files then hold raw wire bytes, not decrypted app data); `tunnel` = a hook's serve-mode decision for the flow; `reason=hook` (plus `dst, detail` — the hook's close reason) marks a hook-blocked connection; `reason=rejected` (plus `dst, detail` — the hook's serve-mode rejection reason) marks a flow refused at establishment |
| `http_request` / `http_response` | `ts, line` — first line only |
| `s2c_drop` | `ts, id, size, limit, start, end` — an s2c chunk of `size` bytes exceeded the `s2c_max_packet` cap and was not forwarded to the client; `start`/`end` are the chunk's offsets into the captured `s2c.bin` (consistent with the `bytes_s2c` range); appears only when the cap is set and isolation is `off`; the same loss is recorded on the flow's capture stream (`pkg/capture`) as a `Dropped` chunk with reason `s2c_max_packet` and `Len` = `size` |
| `bytes_c2s` | `ts, start, end` — single per-flow `[start,end)` byte range written to `c2s.bin`, emitted once at close |
| `bytes_s2c` | `ts, start, end` — one event per write to `s2c.bin`: the `[start,end)` of that write, in write order, cumulative, covering the whole file (offsets consistent with `s2c_drop`); a final summary event covering the whole flow is emitted at close |
| `conn_close` | `ts, id, err` |

The design spec (`docs/superpowers/specs/` in the repo) describes a richer
schema (TLS leg details, HTTP structure, body extraction, byte counts in
`conn_close`); the binary currently writes the subset above.

## index.db

Single table:

```sql
patched(ip TEXT, host TEXT, reason TEXT,
        first INTEGER, last_recheck INTEGER,   -- unix ms
        attempts INTEGER, PRIMARY KEY (ip, host))
```

A row means MITM for that (destination IP, SNI/host) pair was rejected
(`cert_rejected`) or is mTLS (`mtls`); matching connections are relayed raw
until the recheck (default 720 h) clears the row.

## How it is collected

- mangle PREROUTING TPROXY rules divert the client device's traffic to the proxy
  listener; each accepted connection gets its directory at `conn_open`, bytes
  are teed into the `.bin` files in arrival order (decrypted for MITM),
  milestone events are appended, and `conn_close` lands at connection end.
- One keep-alive connection = one directory growing for its whole life —
  **not** one directory per request. Silence in the journal while a
  connection is healthy is normal; the journal carries lifecycle events only.
- Per-direction capture cap: 256 MiB per direction per connection; the first
  direction to hit it freezes both `.bin` files (the cap flag is shared), and
  no marker event is emitted at the moment the cap is hit. The cap bounds
  `.bin` bytes only: `meta.jsonl` keeps being journaled for the connection's
  whole life, including the close summary and any post-cap `s2c_drop` events.
- Retention (daily): day-dirs older than 90 d, or the oldest beyond 200 GiB
  total, are deleted — old captures may simply be gone.
- MITM success means the client accepted a forged leaf signed by a
  compromised intermediate (EM OV TLS CA - G3C); the decrypted bytes are the
  genuine application traffic.
