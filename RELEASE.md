# Release Guide

## Versioning policy

Current public release line is `v0.0.x`.

The native event-loop data plane is the path to the first `v0.1.0` release, but `v0.1.0` should only be cut after:

- Linux runtime validation passes on the epoll path
- timeout and lifecycle hardening are confirmed
- multi-core `wrk` validation is run on a host that actually has multiple vCPUs
- docs and positioning are updated to describe the product honestly

- Start from `v0.0.1`.
- Keep incrementing patch while APIs are stabilizing.
- Do not cut a stable release until namespace/API and runtime behavior are finalized.

## Pre-publish checks

Run from repository root:

```bash
chmod +x scripts/release_check.sh
./scripts/release_check.sh
php -n -l example.php
```

## Build extension artifact

```bash
phpize
./configure --enable-kislayphp_gateway
make -j4
make test
```

## Publish checklist

- Confirm `README.md`, `composer.json`, and `package.xml` are up to date.
- Confirm `package.xml` release and API versions are set correctly.
- Confirm docs reflect current namespace (`Kislay\\...`) and legacy alias compatibility (`KislayPHP\\...`).
- Confirm docs reflect native engine activation via `KISLAY_GATEWAY_ENGINE=auto`, `epoll`, or `kqueue`.
- Confirm docs reflect Linux `epoll` as the primary production path and macOS `kqueue` as the native fallback path.
- Confirm ZTS behavior is documented honestly:
  - direct routes may use worker threads
  - PHP resolvers are rejected on ZTS builds
- Confirm service-route docs prefer `registerService()` for the native production path and describe `setResolver()` as compatibility fallback.
- Confirm observability docs describe `KISLAY_GATEWAY_EPOLL_STATS=1`.
- Confirm release notes list current native-path limitations:
  - HTTP/1.1 only
  - direct routes only
  - no HTTP/2 or HTTP/3
  - TLS upstream path not fully optimized
- Confirm multi-core Linux `wrk` results exist before any `v0.1.0` tag.
- Tag release and push tag to origin.
