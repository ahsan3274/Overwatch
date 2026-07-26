# Overwatch Local EDR Operations

**Updated:** 2026-07-27
**Host:** macOS endpoint
**Status:** Active

## Purpose and operating policy

Overwatch provides local macOS endpoint monitoring, deterministic EDR checks,
local model-assisted triage, and local alerts.

The process watchdog audits an intentional privacy-policy watchlist. It is
non-destructive by default. Termination and unload actions require the explicit
`OVERWATCH_WATCHDOG_ENFORCE=1` environment opt-in; the installed LaunchAgent
pins this value to `0`.

## Active pipeline

1. Objective-See FileMonitor and ProcessMonitor collect file and process events.
2. The network monitor evaluates new connections, suspicious ports, configured
   IP/domain indicators, and possible beaconing.
3. Events are appended to `~/velociraptor-triage/event_queue.jsonl`.
4. `triage_daemon.py` removes expected policy events, filters trusted noise,
   archives stale events, and deduplicates the remaining queue.
5. An exact signed-writer/application-support allowlist scores routine,
   non-executable maintenance without loading the model.
6. Deterministic EDR checks scan executable and persistence-relevant file
   writes using hash reputation and local YARA rules.
7. Events that still need judgment are assessed locally by RedSage through LM
   Studio.
8. Results are written to `scored_events.jsonl`; HIGH and CRITICAL assessments
   are delivered through enabled local alert channels.

Confirmed false-positive exceptions are evaluated before model loading and
again before alert delivery. A match becomes a retained risk-1 assessment and
an entry in `false_positive_audit.jsonl`; it is not silently discarded.

The EDR database complements RedSage. It does not replace model assessment for
novel or ambiguous events.

## Services

System LaunchDaemon:

- `com.velociraptor.processmonitor` — runs
  `~/velociraptor-triage/run_processmonitor.sh` as the Objective-See process
  event collector. Install it with the current user's home directory.

User LaunchAgents:

- `com.velociraptor.processwatchdog` — audit-only Apple-service policy monitor;
- `com.velociraptor.networkmonitor` — network event collection;
- `com.velociraptor.alerter` — scored-event alert delivery;
- `com.velociraptor.llm-triage` — scheduled queue triage.

Operational code is deployed in `~/velociraptor-triage`.

The directory name is historical. No official Velociraptor client process was
observed during the July 22 service audit; the active pipeline is the custom
Python implementation documented here.

## False-positive controls added July 17

### Process watchdog

- Watchlist matching is exact instead of substring-based.
- Failed `kill` and `launchctl` operations are reported accurately.
- Audit/enforcement records use the `policy_enforcement` event type, risk score 1,
  and `expected_policy_enforcement: true`.
- Identical enforcement records are rate-limited to once per hour.
- Triage deterministically excludes watchdog policy records before loading the
  local model.
- The watchdog performs no termination or unload action by default. Explicit
  enforcement uses `SIGTERM`, not an unconditional `SIGKILL`.

### Network monitor

- Beacon detection counts newly observed sockets, not repeated 30-second polls
  of one established socket.
- Connection history is scoped to process, PID, and remote IP.
- Private and loopback addresses are excluded from beacon analysis.
- Frequency alone is a medium-confidence signal (risk 5), not proof of C2.
- Verified local clients and truncated macOS service names are treated as
  trusted where appropriate.

### Triage

- A 24-hour recency heuristic controls live triage. Older or unparseable events
  are archived to `stale_events.jsonl` and are not submitted as live incidents.
- Objective-See FileMonitor timestamps using `YYYY-MM-DD HH:MM:SS +0000` are
  parsed explicitly on Python 3.9, preventing old events from remaining live.
- Full event JSON is passed to RedSage. Missing metadata or PID 0 is explicitly
  not a threat indicator.
- `/tmp` and non-Apple `/Library` activity are no longer hidden by blanket path
  exclusions.
- Permission failures in system-load probes fall back safely instead of
  crashing the scheduled run.
- Empty or policy-only queues are cleared without launching LM Studio.

### Trusted-maintenance fast path

Routine file activity receives a deterministic risk-1
`trusted_maintenance` assessment only when all of these conditions hold:

- the event came from FileMonitor and is a create, write, unlink, or rename;
- FileMonitor computed the writer as signed;
- the writer path exactly matches an explicit allowlist entry;
- the destination is inside that application's exact support directory;
- the destination is not executable, persistence-related, or a risky file
  type.

The current explicit pairs cover Google Chrome, OpenVPN Connect, LibreOffice,
and GitHub Desktop writing their own user application-support data. The event
is still retained in `scored_events.jsonl` and `processed.jsonl`; the fast path
changes analysis cost, not evidence retention.

Unsigned writers, lookalike directories, cross-application writes, process and
network telemetry, executable destinations, `/tmp`, Downloads, LaunchAgents,
LaunchDaemons, and unknown patterns continue to deterministic EDR and/or
RedSage. Adding a new pair requires a reviewed code change and regression test.

### Confirmed false-positive exception registry

`false_positive_exceptions.json` provides a reviewed data-driven registry for
cases that have already been independently validated. Rules must include an ID,
reason, source, event types, a process constraint, and a destination
constraint. Signed file-event exceptions additionally require the exact Apple
Developer team ID and signing ID. Rules can expire and are ignored after their
`expires_at` timestamp.

The initial rules cover only:

- LuLu's signed system extension atomically writing its own temporary
  `rules.plist.sb-*` file;
- Google's signed updater atomically writing its own
  `.com.google.GoogleUpdater.*` state file.

Matching events remain in `scored_events.jsonl` and `processed.jsonl`, receive a
`confirmed_false_positive` assessment, and are copied to
`false_positive_audit.jsonl`. The alerter independently checks the same rule
before delivery as defense in depth.

Validate the registry after any edit:

```sh
python3 ~/velociraptor-triage/false_positive_exceptions.py
python3 -m unittest -v ~/velociraptor-triage/test_overwatch.py
```

Do not create exceptions based only on a familiar directory or process name.
Validate the raw event, computed signature, signer identity, destination, and
expected behavior first. Prefer a short expiry for anything not tied to a
stable signed product identity.

Content hash and YARA scanning is limited to executable or
persistence-relevant writes. This avoids hashing routine databases and sending
irrelevant reputation queries. The EDR engine is reused for a batch. If
MalwareBazaar returns HTTP 404, remote lookups are disabled for that batch
while local YARA checks continue.

## False-positive failure modes addressed

The current controls specifically address these previously observed failure
modes:

- the watchdog was generating thousands of records for expected Apple-service
  enforcement;
- stale records remained in the live queue and were replayed as current events;
- RedSage received only generic PID 0 metadata for watchdog records;
- the network monitor counted the same persistent HTTPS socket on every poll.

These patterns can explain false-positive alerts, but they do not prove that an
event is benign. Investigate new high-confidence alerts using raw event details,
signatures, hashes, and independent logs.

## Evidence retention

Queue maintenance preserves stale evidence in
`~/velociraptor-triage/stale_events.jsonl`; completed assessments remain in
`~/velociraptor-triage/scored_events.jsonl`. Timestamped pre-maintenance
snapshots belong under `~/velociraptor-triage/archives/`.

Operational watchdog and network logs rotate at 5 MB with three backups.

## Local model lifecycle

When actionable events require model assessment, Overwatch starts the LM Studio
server, loads `redsage-qwen3-8b-dpo` once for the batch, and keeps it loaded
during that batch. Final cleanup unloads the model and stops the LM Studio
server, daemon, and GUI. Policy-only and empty queues do not start LM Studio.
Trusted-maintenance-only batches also do not start LM Studio.

Active alerts are local Terminal and macOS notifications, with optional Slack,
Discord, or email only when explicitly configured.

## DarkWake correlation

DarkWake investigation is available on demand by correlating:

- `pmset -g log` wake timestamps, driver reasons, assertions, and wake requests;
- macOS services requesting maintenance, such as `mDNSResponder` and `dasd`;
- Overwatch process, file, and network events around each timestamp.

This produces temporal evidence, not guaranteed causation. Kernel-level
`wifibt` wakes may not identify a user process, and a short connection can fall
between the network monitor's 30-second polling intervals. DarkWakes are not yet
ingested continuously into `event_queue.jsonl`.

## Verification completed

- Python syntax checks passed for the watchdog, network monitor, triage daemon,
  and LM Studio manager.
- Behavioral checks confirmed that a repeated socket poll does not create a
  beacon and that genuine new-connection frequency is scored at risk 5.
- Boundary tests confirmed that an event exactly 24 hours old remains eligible,
  while an event one second older and an unparseable timestamp are archived.
- A `/tmp` create event remained eligible for triage.
- A policy-enforcement event was filtered, the queue cleared, and LM Studio did
  not launch.
- ProcessMonitor launch templates use the selected user's deployment path.
- The scorer's JSON serialization path is covered by a regression test.
- The watchdog's default audit-only mode is covered by tests that assert no
  process termination or launchd unload.
- Trusted-maintenance and EDR scan gates are regression tested.
- Confirmed false positives use structured, expiring signer/process/path rules
  with an audit log and alert-delivery backstop.
- Model lifecycle tests confirm deterministic-only work does not require LM
  Studio and model-assisted batches clean up after completion.

## Useful checks

```sh
launchctl print system/com.velociraptor.processmonitor
launchctl print gui/$(id -u)/com.velociraptor.processwatchdog
launchctl print gui/$(id -u)/com.velociraptor.networkmonitor
launchctl print gui/$(id -u)/com.velociraptor.alerter
launchctl print gui/$(id -u)/com.velociraptor.llm-triage
lsof -nP -iTCP -sTCP:LISTEN
tail -f ~/velociraptor-triage/triage_daemon.log
tail -f ~/velociraptor-triage/alerts.log
python3 ~/velociraptor-triage/archive_queue.py
```

`archive_queue.py` atomically rotates the live queue, preserves newly collected
events, and moves evidence outside the 24-hour live-triage heuristic into
`stale_events.jsonl`. It does not delete archived evidence.

## Maintenance cautions

- Keep the watchdog watchlist intentional; changing it changes macOS feature
  availability.
- Do not set `OVERWATCH_WATCHDOG_ENFORCE=1` without reviewing every watchlist
  entry and accepting the resulting macOS feature disruption.
- Review configured suspicious IP ranges periodically. Broad or stale ranges
  create false positives.
- Do not treat model output alone as confirmation of malware.
- Validate HIGH and CRITICAL events against raw telemetry and deterministic EDR
  evidence before remediation.
- A quiet alert log is not proof of a clean host. Trusted-process exclusions,
  polling intervals, endpoint permissions, and model errors remain detection
  boundaries.
