# eMudhra OV TLS CA (G3C) — incident background

This folder documents the October 2026 eMudhra incident (CVE-2026-111943):
eight intermediate CA keys were small integers (this one: d=4), recoverable
from the public certificates in at most 256 trial multiplications. Browsers
and OSes revoked or blocked the affected certificates around 2026-10-20/21;
public PoCs exist (`beppler/emudhra`, `boostsecurityio/emBarrass`) and the
advisories publish the keys.

`em-ov-tls-ca-g3c-key.pem` (EM OV TLS CA G3C, d=4) is therefore not a
secret. The MITM setup (intermediate + chain + vendor cloud cert) still
works against clients whose trust stores do not track those revocations.

Operate only on networks you own.
