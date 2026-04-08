# kislayphp_gateway tests

Run from repository root:

```sh
make test
```

This runs all `.phpt` cases in `tests/`, including namespace alias and HTTPS target parsing coverage.

Native engine smoke and benchmark harnesses live in `tests/native/`.

Examples:

```sh
KISLAY_GATEWAY_ENGINE=auto tests/native/run_native_smoke.sh
KISLAY_GATEWAY_ENGINE=auto KISLAY_NATIVE_TEST_MODE=service tests/native/run_native_smoke.sh
KISLAY_GATEWAY_ENGINE=auto tests/native/run_native_ab.sh
```
