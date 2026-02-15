# Release Guide

## Pre-publish checks

Run from repository root:

```bash
chmod +x scripts/release_check.sh
./scripts/release_check.sh
```

## Build extension artifact

```bash
phpize
./configure
make -j4
```

## Publish checklist

- Confirm `README.md`, `composer.json`, and `package.xml` are up to date.
- Confirm `package.xml` release and API versions are set correctly.
- Confirm examples pass `php -n -l`.
- Tag release and push tag to origin.
