# RFC Validation Notes for Future Maintainers and AI Agents

## Purpose and baseline

This document explains the reasoning behind the RFC-oriented test improvements
in commit `0ba8b55`, based on upstream commit `4cfc7d2`. It is a guide to the
implemented checks and their limitations, not a conformance certificate or a
record of test results. Recheck the current source before extending any claim.

The evaluated system is iip over IPv4 together with this repository's packet
backend, callbacks, and API adapters. A failure may originate in the target,
the integration, the fixture, or the assertion. Do not attribute every failure
to iip without tracing that path.

All cases currently have partial coverage. Successful execution must not be
reported as complete RFC conformance. The runner deliberately reports
`conformance: NOT_ESTABLISHED`.

## Where to find the implementation

| File | Role |
| --- | --- |
| [requirements.json](requirements.json) | Case IDs, functions, requirement IDs, RFC references, strength, applicability, responsibility, observation criteria, and gaps |
| [main.c](main.c) | Existing scenarios, packet builders, virtual clock, event recording, and isolated execution |
| [conformance_tests.h](conformance_tests.h) | Additional independent observations and explicit algorithm profiles |
| [test_runner.h](test_runner.h) | Case selection, profile selection, TAP/JSON reporting, and exit policy |
| [test_cases.h](test_cases.h) | Generated registry; do not edit manually |
| [test_api.h](test_api.h) and [test_backend.h](test_backend.h) | Integration boundary and implementation-specific access |
| [scripts/generate_cases.py](scripts/generate_cases.py) | Ledger validation and registry generation |
| [scripts/check_mutations.py](scripts/check_mutations.py) | Isolated target mutations and synthetic observer counterexamples |
| [scripts/capture_run.py](scripts/capture_run.py) | Source snapshots, environment, diagnostics, and requirement-grouped evidence |
| [tests/test_reporting.py](tests/test_reporting.py) and [tests/runner_faults.c](tests/runner_faults.c) | Reporting contracts and observation-overflow protection |

Use symbols and case IDs rather than historical line numbers. Several cases
share a function or requirement. Aggregate and independent cases coexist for
compatibility; their counts are not counts of distinct requirements or defects.

## Rules for interpreting requirements

1. Read the normative text and its applicability conditions before changing an
   assertion. Follow the case's RFC reference, including referenced algorithms.
   The ledger is a navigation aid, not an independently verified specification.
2. Separate mandatory behavior, recommendations, optional capabilities, and
   implementation contracts. A selected algorithm's exact counters are not
   automatically universal TCP requirements.
3. Establish valid input and observable execution before interpreting silence
   as rejection, success, or missing functionality.
4. Prefer emitted packets and application-visible callbacks as evidence.
   Internal state can establish preconditions or diagnose failures, but it must
   not manufacture an output that the target never produced.
5. Test both prohibited behavior and permitted alternatives. An assertion that
   rejects a permitted implementation is defective even if it passes locally.
6. Record uncovered conditions explicitly. Finite observations do not prove
   unbounded liveness, cryptographic security, or all-state correctness.

Primary references already associated with this work include
[RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html),
[RFC 1122](https://www.rfc-editor.org/rfc/rfc1122.html),
[RFC 2018](https://www.rfc-editor.org/rfc/rfc2018.html),
[RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html),
[RFC 5681](https://www.rfc-editor.org/rfc/rfc5681.html),
[RFC 7323](https://www.rfc-editor.org/rfc/rfc7323.html), and
[RFC 7413](https://www.rfc-editor.org/rfc/rfc7413.html).
A comprehensive audit of updates and errata remains outstanding.

## State-machine and sequence-number coverage

`test_tcp_model.h` defines expected input processing independently of target
transition/comparison helpers. `test_tcp_traces.h` checks actual OPEN/CLOSE paths and control loss;
`test_tcp_sequence.h` checks six sequence boundaries with wire, callback, and
explicitly classified internal-buffer observations. All ledger coverage remains
partial. `phase: 2` and `phase: 3` are additional machine-readable classifications.

The legacy simultaneous-close scenario incorrectly expected FIN without ACK to
enter CLOSING. RFC 9293 Section 3.10.7.4 drops that input at the ACK-bit check.
It now transmits a real local FIN and receives FIN+ACK that has not yet ACKed
that FIN, requiring CLOSING until the local FIN is acknowledged. The SYN-SENT
reset positive control sends its SYN before accepting the SYN acknowledgment.

Allow PSH on empty control packets, optional passive-reset notifications, and
the permitted reset/challenge-ACK alternatives. Do not turn target failures
into successful observations by requiring the wrong control input. Direct
placement of CLOSING is useful for independent input checks but cannot prove
that actual simultaneous close reaches it.

The receive-window regression queues the last in-window byte, then supplies a
segment covering that byte and extending beyond the window. It checks trimming,
ordered delivery, and receive-buffer accounting. ZERO-WINDOW independently
checks rejection at a full window and delivery after the application consumes
buffered data.

SACK fixtures explicitly enable the capability; negotiation is outside those
cases. Sender SACK observations include the internal scoreboard and retention
until cumulative ACK, not a requirement to implement one particular loss
recovery algorithm. Conflicting overlapping data and invalid SACK blocks remain
separate coverage gaps.

## Fixture and observation preconditions

### Timestamp negotiation and virtual time

`fixture_init` creates a direct ESTABLISHED connection with Timestamp disabled.
Ordinary inputs therefore do not accidentally omit a supposedly negotiated
Timestamp option. Scenarios that need Timestamp explicitly enable it or test
negotiation separately. Do not infer handshake correctness from this fixture.

The workspace clock and fast, slow, and very-slow timer origins are initialized
consistently. Otherwise the first timer call can introduce artificial elapsed
time and distort RTT samples or expiry observations. Drive timing checks with
the virtual clock and actual timer processing, not wall-clock sleeps.

### Complete observation and isolated execution

Event or tracked-connection overflow sets `harness_event_overflow` and becomes
ERROR. A truncated observation history cannot justify PASS. Tests execute in
child processes with a timeout, so one assertion or hang does not hide later
cases. Infrastructure errors and signal failures are not silently converted to
recommendation deviations.

Keep assertions enabled: the harness rejects builds with `NDEBUG`.

## Protocol checks and why they changed

### TIME-WAIT: `MUST-13`

`test_time_wait_2msl` checks that the connection remains in TIME-WAIT just before
2MSL and accepts expiration at the boundary. It also permits the implementation's
next timer tick to perform expiration. Do not demand that a connection remain
open at exactly 2MSL merely because the current implementation uses a strict
comparison. The relevant reference is RFC 9293 Section 3.6.1.

### Delayed ACK and ACK ordering: `MUST-40`, `MUST-58`, `MUST-59`

`test_delayed_ack_limit` observes through 499 ms rather than stopping at 490 ms.
The tested deadline is strictly below 500 ms. The separate aggregation and
out-of-order queue checks inspect cumulative ACK behavior and processing order;
passing the delay check alone does not establish those properties.

Preserve the distinction between RFC 9293 Section 3.8.6.3 (delayed ACK) and
Section 3.10.7.4 (segment processing and queued data). Synthetic ACK scheduling
validates the observer boundary, not the target's own ACK timer implementation.

### Keep-alive: `MUST-24` through `MUST-29`

Probe checks accept zero or one payload byte and verify packet validity.
`test_keepalive_probe_loss` exercises a single missing response and recovery.
Do not require termination after an arbitrary count derived from an unrelated
retransmission parameter, or declare the connection dead from one lost probe.
Configuration, idle conditions, and default behavior remain separate cases.
See RFC 9293 Section 3.8.4.

### Silly Window Syndrome: `MUST-38`, `MUST-39`

Base checks focus on transmission and advertised receive-window behavior.
Receiver observations use the actual initial advertised window, rather than
assuming it equals a private buffer capacity. Exact buffer accounting and
selected sender override-timer behavior are separated into `PROFILE-SWS-RX`
and `PROFILE-SWS-TX`.

A FIN may accompany payload; do not require a separate empty FIN without a
specific applicable contract. Some base SWS helpers still inspect internal
state and require further audit. The split is not a claim that every existing
SWS predicate is now independent of implementation details.

### Nagle: `MUST-17`, `SHLD-7`

`MUST-17` (an application can disable Nagle per connection) and `SHLD-7`
(Nagle is implemented) are separate cases. The control is bound through
`IIP_EX_TCP_SET_NAGLE_DISABLED`, which sets or clears
`II_TCP_CONN_FLAGS_NAGLE_DISABLED`. `MUST-17` checks the default, per
connection toggling, and that a second one-octet write is sent without
waiting for an ACK while the control is set. `SHLD-7` checks that, with the
control clear, the second write is held until the first octet is ACKed and
then sent; not holding it is a recommendation deviation. While Nagle is not
implemented, a `MUST-17` PASS shows only that the control exists and that
disabled behavior is observed, not that the control changes behavior.

`NAGLE-ACK-1`, `NAGLE-DUPACK-1` and `NAGLE-FIN-1` check that Nagle holds
only new small data. iip queues ACK, FIN and RST in the same transmit ring as
data, so a hold that only looks at payload length also holds the control
segment behind it. With one octet outstanding and one held: an ACK for peer
data must leave within 0.5 s (`MUST-40`); an out-of-order segment must cause
an immediate data-less duplicate ACK (RFC 5681, SHOULD); and close must send
the held octet and FIN (implementation profile, no RFC text). The RTO is
pushed out because a retransmission also carries an ACK and would mask a
held control segment. If Nagle does not hold the second write, the cases are
NOT_APPLICABLE.

### MSS and SACK

`MUST-14` does not treat failure to observe an MSS option as sufficient evidence
of a mandatory violation; the scenario can be inconclusive. Effective send MSS
must account for the scenario's actual headers and options. The profile using
Timestamp explicitly enables it instead of relying on the base fixture.

`expect_ack` checks valid SACK encoding and the expected first block for the
legacy scenarios. Later blocks may appear in a different order or number; they
must still describe recognized received ranges. Do not impose one exact list
when the requirement permits alternatives. RFC 2018's first-block rule has
conditions, including cumulative-ACK advancement; do not generalize this helper
to new scenarios without revisiting those conditions.

### Normal close versus abort: `MUST-12`, `TCP-ABORT-2`

`test_abort_notification` compares normal FIN completion with RST abort using
application-visible callback histories. Merely counting a CLOSED callback does
not establish that the application can distinguish normal completion from an
abort.

`test_abort_after_fin_notification` covers the more subtle case where both
histories already include a peer FIN. It compares the completion information
exposed to the application. Do not synthesize an abort reason from the packet
the test injected. If notification fields change, update the comparison to
reflect information genuinely available to the application, not pointer identity
or unrelated internal state.

### RTT, retransmission, and congestion control

`MUST-18` retains Karn-related negative coverage. `TCP-RTT-1` adds a positive,
unambiguous first sample. It explicitly sets a 3-second SYN timer to isolate
sampling from initial-RTO behavior, then measures 400 ms in the implementation's
200 ms estimator units. This does not validate the default initial RTO.

`PROFILE-RTT-2` checks the selected alpha=1/8, beta=1/4 estimator and subsequent
RTO lower bound. Its seeded values, integer units, and exact expected values
are an explicit profile, not a universal representation requirement. Timestamp
sampling and broader rounding/boundary cases remain incomplete. Consult RFC
6298 for sampling, update order, retransmission ambiguity, and timer rules.

`PROFILE-CC-1` exercises multiple saturated flights above ssthresh, checks the
selected Reno-style growth bound, and requires progress. A one-byte ACK or an
upper-bound assertion alone cannot detect an estimator or congestion window
that never grows. This profile does not validate every permitted congestion
control algorithm; consult RFC 5681 and the chosen algorithm's specification.

### Address stability and ICMP attribution

`TCP-ADDR-1` follows a connection through data, retransmission, and FIN while
changing the source-selector candidate. Observe the emitted source address
throughout the connection, not only during initial selection.

`fixture_prepare_icmp` captures a real transmitted IPv4 header and the required
initial transport bytes for quotation. A fabricated quoted sequence number can
miss the target's connection/error validation path and create a false failure.
Recompute affected checksums when modifying a quotation.

`TCP-ICMP-*` cases separate notification observations by ICMP type and code.
Trace matching, callback invocation, and event storage before blaming the TCP
implementation. Upstream commit `4cfc7d2` supplies
`IIP_OPS_TCP_ICMP_RECEIVED_ERROR` and `test_event_tcp_icmp_error`; preserve that
integration. A prior run without the hook is not evidence about a run with it.

### Source routing: `MUST-51`, `MUST-52`

The harness route table is bound to iip through `IIP_OPS_IPV4_OPT_SEND`
(`test_backend.h`/`test_backend.c`). The hook supplies the IPv4 option bytes
and replaces the IPv4 header destination with the first hop; the TCP
pseudo-header keeps the ultimate destination. Routes are keyed by address
pair because the hook runs before the L4 header is copied. `MUST-51` checks
SYN, handshake ACK and a data segment for the option, first-hop destination,
frame length equal to the IPv4 total length, and valid IPv4/TCP checksums.
`MUST-52` delivers a SYN-ACK carrying a different LSRR and requires the
handshake ACK and data to keep the application route. A control connection
without an application route must adopt the received route; otherwise the
verdict is inconclusive, because precedence would not be observable. The old
helper checks remain under `PROFILE-ROUTE-1/2`.

### TFO and independent boundary cases

TFO is an enabled evaluation profile by default; `--no-tfo` explicitly excludes
it. Do not convert every TFO failure into TODO or infer unsupported capability
from a failure after a valid capability precondition.

`TFO-2A`, `TFO-2B`, and `TFO-2C` independently exercise SYN data without an option,
a cookie request, and an invalid cookie. Selected stricter option/API behavior
remains in an implementation profile. `ROBUST-BOUNDARY-*` similarly separates
control, checksum, truncation, flags, MSS boundaries, and payload observations.
Keep independent cases runnable without an earlier case initializing state.

### Bounded observations of liveness: `MUST-60`

`test_no_indefinite_buffering` observes progress over a finite interval. It must
not equate a requirement against indefinite buffering with immediate output or
an arbitrary universal deadline. An unresolved finite observation is
inconclusive. Avoid forcing PSH simply to make an unrelated buffering check pass.

## Reporting contracts to preserve

PASS applies only to the executed scenario. FAIL includes mandatory and selected
profile assertions; DEVIATION represents a SHOULD recommendation failure;
NOT_APPLICABLE needs an applicability reason; INCONCLUSIVE represents missing
preconditions or evidence; ERROR represents execution or observation failures.
A crash must not become a harmless SHOULD deviation.

The exit policy is 0 for no FAIL/INCONCLUSIVE/ERROR, 1 for FAIL or INCONCLUSIVE,
2 for ERROR, and 3 for an otherwise successful `--conformance` run whose coverage
still cannot establish conformance. The requirement ID, strength, profile,
coverage, reason, and ledger hash must remain traceable in structured output.

## Counterexamples and mutation evidence

The following experiments are implemented in `scripts/check_mutations.py`.
They describe expected outcomes, not results of a new run.

| Experiment | Case | Expected observation | Kind |
| --- | --- | --- | --- |
| Expire TIME-WAIT exactly at 2MSL | MUST-13 | PASS | Permitted target behavior |
| Expire TIME-WAIT early | MUST-13 | FAIL | Target defect |
| Freeze first RTT initialization | TCP-RTT-1 | FAIL | Target defect |
| Disable TCP checksum verification | MUST-3 | FAIL | Target defect |
| Reject missing TS when TS is enabled | ROBUST-BOUNDARY-CONTROL | PASS with base TS-disabled fixture | Fixture compatibility control |
| Schedule synthetic ACK at 495/499 ms | MUST-40 | PASS | Observer counterexample |
| Schedule synthetic ACK at 500 ms | MUST-40 | FAIL | Observer counterexample |

The script operates on isolated copies and checks an unmodified control before
each variant. A compile failure is not successful defect detection. Mutation
patches depend on target source anchors; review an anchor mismatch rather than
weakening matching or silently skipping the experiment.

Additional target mutations for SACK ordering, missing termination information,
and invalid TFO-cookie acceptance remain to be implemented.

## Workflow for subsequent changes

1. Read the selected case's ledger entry, source function, and normative text.
   Specify the exact precondition, permitted outcomes, and observable failure.
2. Trace packet delivery and callback wiring. Establish a positive control for
   negative tests, especially checksum, ICMP, option, and filtering cases.
3. Modify a focused scenario; separate implementation profiles where needed.
   Record concrete gaps rather than claiming complete coverage.
4. Update `requirements.json`, run `make registry`, and check with
   `make check-registry`. Never hand-edit `test_cases.h`.
5. Run the independent case and `make check-harness`. Shared fixture changes
   require the affected suites; packet, parser, ownership, or adapter changes
   also warrant ASan/UBSan. Add a meaningful forbidden/permitted counterexample.
6. Capture the source version and configuration for each run. Do not reuse
   historical counts after a rebase, callback change, or target update.
7. Keep target fixes distinct from corrections to the test oracle. Explain why
   each changed outcome is now justified by the applicable requirement.

Example commands:

```sh
make check-harness
./ai-test-iip --case MUST-13 --case MUST-40 --json /tmp/selected-cases.json
make check-mutations
make check-asan
make check-ubsan
python3 scripts/capture_run.py --output artifacts/review-run -- ./ai-test-iip
```

The capture directory is overwritten when reused. Preserve source snapshots,
configuration, diagnostics, and `requirements-report.json` together. Local
artifacts and untracked planning documents may be absent in another checkout;
this guide does not depend on them. GitHub workflow files are not part of the
implementation commit described here.

Before claiming broader conformance, address the remaining API bindings,
state/sequence/time wraparound coverage, Timestamp RTT behavior, algorithm
variants, applicability and SHOULD-deviation analysis, cryptographic assessment,
and RFC update/errata audit. Keep `NOT_ESTABLISHED` until the evidence and scope
justify a different claim.


## Exact-size malformed input and recovery

The 134 `phase: 4` entries in `requirements.json` map `MAL-*` IDs to RFC 791
§§3.1–3.2, RFC 768, RFC 1122 §§3.2.1.2/4.1.3.4, and RFC 9293 §§3.1/3.2/3.10.7.4.
`test_malformed.h` supplies independent byte/checksum builders, exact receive
allocations, post-input TCP/UDP recovery observations, constrained seeded
malformed generation, and legal minimum/maximum controls. No input filtering
adapter is enabled. All entries remain partial coverage and explicitly use a
robustness/capacity PROFILE; RFC 9293 graceful handling does not mandate the
particular drop/reset policy selected for illegal options.

UDP cases exercise illegal Length values with checksum zero, including
header-only datagrams. The observer bounds its payload read without suppressing
an invalid delivery callback. TCP payload bytes are checked individually; UDP
observations cover callback count, length and first byte only. Clean FIN-WAIT
controls distinguish baseline data handling from post-malformed-input recovery.

Illegal options may be dropped or reset under the selected profile. Reset
recovery uses a fresh tuple in the same workspace. Maximum-size IPv4 input uses
two fragments to respect the packet API's uint16 Ethernet length. Large-datagram
acceptance is a selected capacity profile, not a universal RFC requirement.
See [README.md](README.md#malformed-input-and-recovery) for commands and scope.

## Strict API applicability

ROBUST-6/9 assert undocumented internal allocation-failure atomicity, not an RFC
TCP contract. They run only with `--strict-api` or
`IIP_TEST_STRICT_API_CONTRACT=1`; unselected cases are NOT_APPLICABLE.

## Advertised receive-window preconditions

Placed TCP model inputs derive the right edge from an emitted TCP window field
with scale zero, not the internal receive-buffer capacity. Sequence window
cases first emit and verify window=8; failed advertisement is INCONCLUSIVE.
The reopen positive control also requires an advertisement. Crash reports
include the exact active step. RFC 9293 §§3.4 and 3.10.7.4 define the exclusive
right edge as RCV.NXT + RCV.WND.

## Covered pending receive regression

`TCP-RX-PENDING-COVERED-00000000/FFFFFFFF` inject S+7 (one byte), then
S..S+7 (eight bytes), then the S+8 positive control. They require nine ordered
bytes and RCV.NXT=S+9 without changing receive capacity. They are robustness
PROFILE cases grounded in RFC 9293 §3.10.7.4, included in `make check-phase4`
and `make check-phase4-asan`. To isolate the ASan reproducer:

```sh
make ai-test-iip-asan
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 ./ai-test-iip-asan --case TCP-RX-PENDING-COVERED-00000000 --case TCP-RX-PENDING-COVERED-FFFFFFFF
```

## Same-state malformed recovery controls

Recovery compares TCP bytes/callbacks/sequence/state and UDP callback/length/data
with a fresh clean fixture in the same state. If the control cannot deliver
valid data but recovery matches it, the result is INCONCLUSIVE and references
`MAL-VALID-ESTABLISHED`, `MAL-VALID-FIN-WAIT1`, or `MAL-VALID-FIN-WAIT2`.
Unexpected malformed delivery, forbidden output, state corruption, crashes,
and differences from the control remain failures even if that control fails.
Fuzzing retains every non-PASS packet and the clean result in its metadata;
FAIL takes precedence over INCONCLUSIVE within a fuzz batch. The FIN-WAIT
delivery gap is reported by the clean controls, not counted as malformed damage.
This refines a test-defined recovery profile; RFC 9293 §3.10.7.4 and RFC 768
packet-validation expectations are unchanged.

## Consistent placed closing states

CLOSE-WAIT/CLOSING/LAST-ACK/TIME-WAIT place RCV.NXT after the peer FIN
(10001, with FIN at 10000). All locally closed states transmit a real FIN;
FIN-WAIT-2/TIME-WAIT acknowledge it before placement. TCP-TRACE-* separately
checks reachability. This follows FIN sequence consumption in RFC 9293
§§3.4 and 3.10.7.4; placement alone is not a transition test.

## TIME-WAIT SYN alternatives

TCP-MODEL-TIME-WAIT-SYN accepts reset, challenge ACK, or a valid SYN-ACK
with a SYN-RECEIVED child. Under RFC 1122 §4.2.2.13 the new **local ISS** must
exceed the previous local sequence maximum; it is not a comparison between
the incoming SYN SEQ and the previous peer maximum. The case checks that
local condition and acknowledgment. Old-duplicate rollback remains a coverage
gap. RFC 9293 §3.10.7.4 retains reset/challenge alternatives.

## Requirement strength and independent ACK observations

The original 204 TCP-MODEL/TCP-SEQ/TCP-TRACE entries (186 MUST and 18 PROFILE)
were audited against the cited processing text. Each now has `strength_basis`.
`PROTOCOL` identifies ordinary protocol instructions without claiming an
unconditional uppercase BCP 14 MUST. Violations remain FAIL. In particular,
ignoring post-FIN text is an instruction, not an optional action. Exact-RCV.NXT
RST cases retain MUST; the optional RFC 5961 branch has an explicit MUST to
reset, and legacy processing has the same outcome. Simultaneous open retains MUST
under RFC 9293 §3.5 (MUST-10/11).

The lowercase should for unacceptable-segment ACKs in RFC 9293 §3.10.7.4
is recorded as a recommendation with reporting strength SHOULD. RFC 9293 §2.1
reserves BCP 14 meaning for capitals: this label does not invent a normative
uppercase keyword. The general description in §3.5.2 uses lowercase must;
these cases follow the more specific receive algorithm. State/sequence and
discard checks are separate -STATE cases; RX-FIN retains original FIN handling
and has a separate -ACK case for the duplicate. Active/passive loss traces
likewise separate duplicate SYN/FIN ACKs into recommendation cases. Failed ACK preconditions are
INCONCLUSIVE, never downgraded protocol failures. Crashes remain FAIL (or ERROR
for a nonzero child exit, including sanitizer termination).

RFC 5961 §4.2 recommends selecting SYN mitigation (SHOULD) and then requires
the challenge response (MUST). RFC 9293 §3.10.7.4 retains legacy reset for
non-adopters. The SYN cases accept the permitted union as PROTOCOL; they do
not claim that challenge ACK is universally required or demote a broken reset.

