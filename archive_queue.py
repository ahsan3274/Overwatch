#!/usr/bin/env python3
"""Atomically archive queue events outside the live-triage recency window."""

from __future__ import annotations

import json
import os
from pathlib import Path

from triage_daemon import (
    EVENT_QUEUE,
    STALE_LOG,
    LIVE_EVENT_LOOKBACK_HOURS,
    partition_stale_events,
)


def read_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    events: list[dict] = []
    malformed: list[str] = []
    with path.open() as stream:
        for line in stream:
            raw = line.rstrip("\n")
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                malformed.append(raw)
                continue
            if isinstance(event, dict):
                events.append(event)
            else:
                malformed.append(raw)
    return events, malformed


def append_jsonl(path: Path, events: list[dict]) -> None:
    if not events:
        return
    with path.open("a") as stream:
        for event in events:
            stream.write(json.dumps(event) + "\n")


def main() -> None:
    snapshot = EVENT_QUEUE.with_name(
        f".{EVENT_QUEUE.name}.archive-{os.getpid()}"
    )

    # Rotation is atomic. Collectors immediately append to the new queue while
    # this stable snapshot is classified.
    os.replace(EVENT_QUEUE, snapshot)
    EVENT_QUEUE.touch(mode=0o644)

    try:
        events, malformed = read_jsonl(snapshot)
        live, archived = partition_stale_events(events)
        append_jsonl(STALE_LOG, archived)

        # Preserve malformed lines as explicit evidence rather than losing them.
        append_jsonl(
            STALE_LOG,
            [
                {
                    "source": "queue_maintenance",
                    "archive_reason": "malformed_json",
                    "raw_line": line,
                }
                for line in malformed
            ],
        )

        # Use append mode so events collected after rotation remain intact.
        append_jsonl(EVENT_QUEUE, live)
    except Exception:
        # A failed maintenance pass must not strand the snapshot.
        with snapshot.open() as source, EVENT_QUEUE.open("a") as destination:
            for line in source:
                destination.write(line)
        raise
    else:
        snapshot.unlink()

    print(json.dumps({
        "lookback_hours": LIVE_EVENT_LOOKBACK_HOURS,
        "input_events": len(events),
        "live_events": len(live),
        "archived_events": len(archived),
        "malformed_lines_archived": len(malformed),
    }))


if __name__ == "__main__":
    main()
