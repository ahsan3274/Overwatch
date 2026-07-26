# Overwatch local endpoint monitoring

Overwatch is a custom macOS monitoring and triage pipeline. It combines
Objective-See process/file telemetry, a polling network monitor, deterministic
IOC/YARA checks, and local RedSage assessment through LM Studio.

This directory is named `velociraptor-triage`, but the active processes are
custom Python services; this is not evidence that an official Velociraptor
client is running.

## Current operating state

- File, process, and network collectors append to `event_queue.jsonl`.
- Only events within the 24-hour live-triage heuristic reach current scoring.
- Older or unparseable events are preserved in `stale_events.jsonl`.
- `archive_queue.py` performs atomic queue maintenance without dropping newly
  collected events.
- The process watchdog is audit-only. The installed LaunchAgent explicitly sets
  `OVERWATCH_WATCHDOG_ENFORCE=0`.
- The RedSage scorer processes a batch and then unloads the model and closes LM
  Studio.
- Exact signed applications maintaining non-executable data in their own
  reviewed support directories receive deterministic low-risk scores without
  launching LM Studio. All evidence is retained.
- Confirmed false positives can be added to
  `false_positive_exceptions.json` as narrow, expiring signer/process/path
  rules. Matches remain available in `false_positive_audit.jsonl`.
- Executable, persistence-related, unsigned, cross-application, network, and
  unfamiliar activity remains on the full EDR/model path.
- HIGH and CRITICAL assessments go to configured local alert channels.

## Documentation

- [OVERWATCH_OPERATIONS.md](OVERWATCH_OPERATIONS.md) — authoritative operating
  guide for service state, deterministic EDR controls, verification, and
  limitations.

## Install

Install Objective-See FileMonitor and ProcessMonitor plus LM Studio first, then
run the installer from this repository:

```sh
bash setup.sh
```

The installer deploys code to `~/velociraptor-triage`, creates a local alert
configuration from `alert_config.example.yaml`, and installs the scheduled
triage LaunchAgent. Review that local configuration before enabling webhook or
email channels. Runtime evidence, credentials, caches, and threat databases are
excluded from version control.

## Routine checks

```sh
python3 -m unittest -v ~/velociraptor-triage/test_overwatch.py
python3 ~/velociraptor-triage/false_positive_exceptions.py
python3 ~/velociraptor-triage/archive_queue.py
tail -f ~/velociraptor-triage/triage_daemon.log
tail -f ~/velociraptor-triage/alerts.log
```

DarkWake correlation is currently an on-demand forensic workflow using macOS
power logs plus Overwatch timestamps. It is not yet a continuous collector.
