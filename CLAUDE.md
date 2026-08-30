# kislayphp/gateway — notes for AI assistants

Edge-only HTTP gateway: routing, JWT/legacy-bearer auth, rate limiting,
circuit breaking, forwarding to backend services (native `discovery`
integration or a static route table). Single source file:
`kislayphp_gateway.cpp`, built on civetweb. Deliberately does *not*
duplicate `core`'s runtime — this is an edge/proxy layer, not an app
server.

## Auth: two paths, both must stay constant-time

`kislayphp_gateway_begin_request()` supports two auth modes: JWT (HS256,
when `jwt_secret` is configured) and a legacy plain bearer token
(`KISLAY_GATEWAY_AUTH_TOKEN` env var) otherwise. **Both comparisons must be
constant-time** — a plain `!=`/`strcmp` on a secret comparison is a timing
side-channel an attacker can use to recover the secret byte-by-byte via
repeated timing measurements. The JWT path already did this correctly
(explicit HMAC signature comparison with its own explanatory comment); the
legacy bearer-token path did **not** until 2026-08-30 — found by literally
reading the two auth branches side by side and noticing the asymmetry, not
by an automated scanner. Fixed via `kislay_gateway_constant_time_equals()`
(always walks the full length of both inputs, ORs in a length-mismatch
flag rather than early-returning on it — see its comment at the top of
that function for why). **If you add a third auth mode, use that same
helper for the comparison; don't reintroduce a plain string compare on
anything secret.** Regression test: `tests/legacy_bearer_auth_test.phpt`.

## Other things worth knowing before changing this file

- The rate limiter keys its map by an FNV-1a hash with no collision
  detection — reviewed 2026-08-30 and judged not practically exploitable
  (64-bit hash space) rather than a real bug, but worth knowing if you're
  extending rate-limiting logic: a hash collision would incorrectly share
  one caller's rate-limit bucket with another's.
- The connection pool to backend services is `thread_local` — no
  cross-thread synchronization needed there by design, don't add a mutex
  around it without understanding why it's thread_local first.
- The JWT `sub`/`roles` extraction previously had a claim-confusion bug (a
  decoy payload field could leak into another claim after a false key
  match) — already fixed; if you touch JWT claim parsing, re-read that
  fix's reasoning before changing the key-matching logic.
- Nagle/`tcp_nodelay` was previously missing on the civetweb listener
  (same class of bug found in `socket`/`eventbus`) — already fixed; the
  `listen()` method sets `tcp_nodelay` explicitly. Don't remove it.

## Testing

Standard phpt, `make test`. 5/5 as of 2026-08-30 (was 4/4 before the
constant-time bearer-token fix added a 5th).

## Known open issues

None specific to this module as of 2026-08-30.
