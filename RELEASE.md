# Release Guide

## Versioning policy

Current release line is `v0.0.x`.

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
- Confirm ZTS behavior is documented honestly:
  - direct routes may use worker threads
  - PHP resolvers are rejected on ZTS builds
- Tag release and push tag to origin.
