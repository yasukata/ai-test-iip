# ai-test-iip

A test harness for the [iip](https://github.com/yasukata/iip) TCP/IP stack. It covers TCP, UDP, and ICMP over IPv4; TCP state transitions and sequence-number boundaries; malformed packets; reproducible fuzzing; and harness self-tests. [`requirements.json`](requirements.json) records each case's requirement, references, applicability, oracle, and coverage limits.

## Repository layout

| File or directory | Purpose |
| --- | --- |
| `main.c` | Entry point, packet construction, shared helpers, and self-tests |
| `test_api.c` / `test_api.h` | Adapters and helpers for the iip API |
| `test_backend.c` / `test_backend.h` | Packet backend and callbacks |
| `test_wire.h` | Test-side wire-format definitions |
| `test_fixture.h` | Connection fixtures and assertions |
| `test_tcp.h` / `test_tcp_*.h` | TCP feature scenarios, state models, connection traces, and boundary cases |
| `test_ipv4.h` / `test_malformed.h` | IPv4 and ICMP scenarios, malformed inputs, and recovery scenarios |
| `conformance_tests.h` | Additional protocol and API scenarios |
| `test_process.h` | Child-process isolation, timeouts, and result transport |
| `test_runner.h` / `test_report.h` | Case selection, profile control, and TAP/JSON output |
| `requirements.json` | Case definitions and requirements ledger |
| `test_cases.h` | C registry generated from the ledger |
| `run_tests.py` | TAP validation, console output, and log capture |
| `scripts/` | Registry generation, run capture, phase selection, and mutation experiments |
| `tests/` | Harness tests for reporting, process management, and the wrapper |
| `Makefile` | Build and execution targets |

The scenario headers and implementation files are included by `main.c` and compiled as a single translation unit. The iip and BLAKE2 sources are not included in this repository.

## Requirements and dependencies

Use a POSIX environment, a C compiler supporting GNU C11, Git, Make, and Python 3. Sanitizer targets require a compiler and runtime supporting AddressSanitizer or UndefinedBehaviorSanitizer.

Fetch the dependency sources from the repository root:

```sh
git clone https://github.com/yasukata/iip.git iip
git clone https://github.com/BLAKE2/BLAKE2.git blake2-upstream
cp blake2-upstream/ref/blake2.h .
cp blake2-upstream/ref/blake2-impl.h .
cp blake2-upstream/ref/blake2s-ref.c .
```

The build requires `iip/main.c` and `blake2.h`, `blake2-impl.h`, and `blake2s-ref.c` in the repository root. These sources remain subject to their upstream licenses.

## Build and basic usage

```sh
make
./ai-test-iip
```

You can also compile directly:

```sh
cc -std=gnu11 -O2 -Wall -Wextra -o ai-test-iip main.c
```

The harness uses assertions and cannot be built with `NDEBUG` defined. The Makefile accepts `CC`, `CPPFLAGS`, `CFLAGS`, and `PYTHON` overrides. `make clean` removes the regular, ASan, and UBSan executables.

### Selecting cases

```sh
./ai-test-iip --list
./ai-test-iip --case MUST-13 --case MUST-40 --json results.json
./ai-test-iip --no-tfo
./ai-test-iip --strict-api
./ai-test-iip --fast-open
./ai-test-iip --self-tests
```

| Option | Behavior |
| --- | --- |
| `--list` | Show case IDs, profiles, references, and descriptions |
| `--case ID` | Select a case; may be repeated |
| `--json PATH` | Save JSON in addition to TAP output |
| `--no-tfo` | Disable TCP Fast Open cases |
| `--fast-open` | Select only cases whose IDs start with `TFO-` |
| `--strict-api` | Enable the `strict-api` profile |
| `--blake2` | Explicitly enable the BLAKE2 profile, which is enabled by default |
| `--conformance` | Return exit code 3 when comprehensive conformance remains unestablished and there are no other errors |
| `--self-tests` | Run harness self-tests; specify this option alone |

The `base`, `tfo`, `regression`, and `blake2` profiles are enabled by default. Enable `strict-api` with `--strict-api` or `IIP_TEST_STRICT_API_CONTRACT=1`. Cases in a disabled profile are reported as `NOT_APPLICABLE` with a reason.

Each protocol case runs in a child process with a 30-second timeout. Self-tests have a 10-second timeout, with an additional one-second grace period enforced by the parent. Self-tests cover packet construction, event recording, and two-endpoint connection establishment, bidirectional data transfer, and teardown.

### Make targets

| Command | Purpose |
| --- | --- |
| `make check` | Run the regular build and save a log to `test-results.log` |
| `make check-asan` / `make check-ubsan` | Run each sanitizer build and save its log |
| `make check-sanitizers` | Run the ASan and UBSan builds |
| `make check-harness` | Run self-tests, Python tests, and synthetic runner cases |
| `make check-harness-asan` / `make check-harness-ubsan` | Run synthetic harness cases under each sanitizer |
| `make check-harness-sanitizers` | Run those harness cases under both sanitizers |
| `make check-phase4` | Run cases marked `phase: 4` in the ledger |
| `make check-phase4-asan` / `make check-phase4-ubsan` | Run the same phase under each sanitizer |
| `make check-mutations` | Run mutation experiments |
| `make check-conformance` | Run with `--conformance` and capture the sources and run artifacts |

Set `TEST_OUTPUT_FLAGS=--verbose` for more detailed `make check` output. `run_tests.py` parses TAP from stdout and saves it alongside stderr in the log. Empty, truncated, or inconsistent TAP is treated as an output error. Run `--list` and `--self-tests` directly, without this wrapper. Sanitizer targets stop on detected errors; ASan leak detection is disabled.

### Output and exit codes

Normal case runs write TAP to stdout and diagnostics to stderr. JSON records each case's status and reason, the configuration, the ledger hash, and summary counts.

| Status | Meaning |
| --- | --- |
| `PASS` | The scenario satisfied its assertions |
| `FAIL` | A mandatory condition or selected profile condition failed |
| `DEVIATION` | A recommendation treated as `SHOULD` was not satisfied |
| `NOT_APPLICABLE` | The case is inapplicable or an optional profile is disabled |
| `INCONCLUSIVE` | A required capability, precondition, API binding, or observation is unavailable |
| `ERROR` | Execution, recording, or reporting failed |

Exit codes for normal case runs are:

| Code | Condition |
| --- | --- |
| `0` | No `FAIL`, `INCONCLUSIVE`, or `ERROR`, and `--conformance` was not specified |
| `1` | At least one `FAIL` or `INCONCLUSIVE` |
| `2` | Execution or output error, or invalid arguments |
| `3` | None of the above errors, and `--conformance` was specified |

`ERROR` takes precedence over `FAIL` and `INCONCLUSIVE`. `DEVIATION` and `NOT_APPLICABLE` alone do not produce exit code 1.

### Capturing run artifacts

```sh
make check-conformance
python3 scripts/capture_run.py --output artifacts/my-run -- ./ai-test-iip --no-tfo
```

The capture includes source snapshots, hashes, revisions, diffs, environment settings, TAP, JSON, diagnostics, the exit code, and a report grouped by requirement. `make check-conformance` writes to `artifacts/conformance/`. The phase 4 targets write to `normal/`, `asan/`, or `ubsan/` under `artifacts/phase4/`. Reusing an output directory overwrites its files.

## Reproducible fuzzing and malformed inputs

Fuzzing uses a deterministic seed. Environment variables control the seed, case count, and failure artifact prefix:

```sh
IIP_FUZZ_SEED=0x12345678 \
IIP_FUZZ_CASES=1000 \
IIP_FUZZ_FAILURE_PREFIX=./iip-fuzz-failure \
./ai-test-iip
```

Saved inputs use `.bin` files; matching `.txt` files record metadata such as the seed and case number. Phase 4 fuzzing also saves non-`PASS` inputs, including state and clean-control information.

Malformed-input scenarios cover buffers sized to the input, truncated headers, invalid lengths and options, fragmentation boundaries, and IPv4 datagram size boundaries. After a malformed input, they send valid TCP or UDP packets through the same workspace and compare observations with a clean fixture in the same state. A recovery observation matching a control that cannot receive valid input is `INCONCLUSIVE`; unexpected delivery, state corruption, and differences from the control are evaluated separately.

<a id="evaluation-scope"></a>

## Evaluation scope and case design

The evaluated system combines iip over IPv4 with this repository's callbacks, packet backend, and API adapters. IPv6 is outside the scope. Each case observes a finite set of conditions; the suite does not certify comprehensive RFC conformance. JSON reports `conformance: NOT_ESTABLISHED`.

- `TCP-MODEL-*` compares inputs to placed connection states against an independent model.
- `TCP-TRACE-*` exercises actual connection establishment, teardown, and control-packet loss.
- `TCP-SEQ-*` covers sequence-number boundaries, ACKs, retransmission, windows, and SACK.
- Dedicated scenarios cover malformed inputs, recovery, receive reordering and duplication, and clock and sequence-number wraparound.

Cases that place a state directly and traces that reach it through transitions provide different observations. Receive-window boundary cases use an emitted advertised window as a precondition rather than relying only on internal buffer capacity. If a required precondition cannot be observed, the case is `INCONCLUSIVE`.

`IP4-OPT-2` uses a test-side adapter for IPv4 option validation and ICMP Parameter Problem generation. `UDP-PORT-1` uses test-side port binding and a callback for ICMP Port Unreachable generation. These cases do not measure those features as native iip functionality. The `strict-api` profile includes API contracts selected by the test suite; the BLAKE2 case does not establish cryptographic security.

The ledger records requirement strength in `strength` and, for applicable cases, `strength_basis`. `PROTOCOL` denotes a protocol processing instruction, while `PROFILE` denotes a selected test condition; violations of either are reported as `FAIL`. Some cases separate recommended ACK observations from state and delivery conditions. See each entry's `applicability`, `oracle`, and `gaps` for its preconditions and limits.

## Adding or updating cases

1. Add or update the test in the appropriate scenario header.
2. Update its definition, references, oracle, and limits in `requirements.json`.
3. Generate `test_cases.h` with `make registry`.
4. Check that the ledger and generated registry match with `make check-registry`.

Do not edit `test_cases.h` directly. The ledger's `phase` field selects cases for phase-specific runs; it does not change the default profile selection. Scenarios can use `TEST_REQUIRE`, and Boolean helpers can use `TEST_CONDITION` or `TEST_ACCUMULATE`, to include expected and observed values in diagnostics.

## Generation history and license

The original implementation and README were generated by OpenAI Codex. The initial malformed-input, boundary-value, TCP state-transition, reproducible-fuzzing, control-case, and RFC section-mapping extensions were attributed in commit `f55f240` to M365 Copilot based on the GPT-5 reasoning model. Several later commits identify Microsoft 365 Copilot (Claude), while other commits identify OpenAI Codex or Microsoft Copilot without naming an underlying model. Subsequent work was contributed through these tools; the commit history does not establish a single model for the entire repository.

This project is licensed under the [MIT License](LICENSE).
