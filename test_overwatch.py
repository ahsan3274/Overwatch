import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import lmstudio_manager
import triage_daemon
import false_positive_exceptions
from edr import hash_lookup
from process_watchdog import ProcessWatchdog


class LMStudioManagerTests(unittest.TestCase):
    @patch.object(lmstudio_manager.requests, "post")
    def test_score_threat_serializes_event_and_parses_json(self, post):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "choices": [{"message": {"content": json.dumps({
                "risk_score": 2,
                "reasoning": "Expected system activity",
                "threat_type": "benign",
                "confidence": 0.9,
            })}}]
        }
        post.return_value = response

        manager = lmstudio_manager.LMStudioCLIManager()
        manager.ensure_loaded = Mock(return_value=True)
        result = manager.score_threat(
            {"source": "test", "event_type": "benign"},
            unload_after=False,
        )

        self.assertEqual(result["risk_score"], 2)
        self.assertEqual(result["threat_type"], "benign")
        post.assert_called_once()


class ProcessWatchdogTests(unittest.TestCase):
    @patch("process_watchdog.subprocess.run")
    def test_audit_mode_never_invokes_kill_or_launchctl(self, run):
        watchdog = ProcessWatchdog(enforcement_enabled=False)

        self.assertFalse(watchdog.kill_process(123, "cloudd"))
        self.assertFalse(watchdog.unload_launchd_job("/tmp/example.plist"))
        run.assert_not_called()

    def test_audit_event_records_no_action(self):
        watchdog = ProcessWatchdog(enforcement_enabled=False)
        event = watchdog.create_event([{
            "watchlist_name": "cloudd",
            "pid": 123,
        }])

        self.assertFalse(event["enforcement_enabled"])
        self.assertIn("Audit only", event["action_taken"])
        self.assertFalse(event["flagged"])


class EventAgeTests(unittest.TestCase):
    def test_parses_filemonitor_timestamp(self):
        parsed = triage_daemon.parse_event_timestamp(
            "2026-07-19 14:10:53 +0000"
        )

        self.assertEqual(
            parsed,
            datetime(2026, 7, 19, 14, 10, 53, tzinfo=timezone.utc),
        )

    def test_24_hour_heuristic_archives_old_and_unknown_events(self):
        now = datetime(2026, 7, 23, 12, 0, 0, tzinfo=timezone.utc)
        recent = {"id": "recent", "timestamp": "2026-07-23 11:00:00 +0000"}
        boundary = {"id": "boundary", "timestamp": "2026-07-22 12:00:00 +0000"}
        old = {"id": "old", "timestamp": "2026-07-22 11:59:59 +0000"}
        unknown = {"id": "unknown", "timestamp": "not-a-timestamp"}

        live, archived = triage_daemon.partition_stale_events(
            [recent, boundary, old, unknown],
            now=now,
        )

        self.assertEqual([event["id"] for event in live], ["recent", "boundary"])
        self.assertEqual([event["id"] for event in archived], ["old", "unknown"])


class TriageOptimizationTests(unittest.TestCase):
    def chrome_event(self, **overrides):
        event = {
            "source": "filemonitor",
            "event_type": "file_write",
            "path": (
                str(triage_daemon.Path.home())
                + "/Library/Application Support/Google/Chrome/Safe Browsing/"
                + "UrlSubresourceFilter.store"
            ),
            "process": triage_daemon.CHROME_BINARY,
            "signing_status": "signed",
        }
        event.update(overrides)
        return event

    def test_exact_signed_chrome_maintenance_uses_fast_path(self):
        score = triage_daemon.deterministic_maintenance_score(self.chrome_event())

        self.assertEqual(score["risk_score"], 1)
        self.assertTrue(score["deterministic_fast_path"])

    def test_unsigned_or_lookalike_chrome_event_requires_analysis(self):
        unsigned = self.chrome_event(signing_status="unsigned")
        lookalike = self.chrome_event(
            path=str(triage_daemon.Path.home())
            + "/Downloads/Chrome/Safe Browsing/payload"
        )

        self.assertIsNone(triage_daemon.deterministic_maintenance_score(unsigned))
        self.assertIsNone(triage_daemon.deterministic_maintenance_score(lookalike))

    def test_executable_destination_never_uses_fast_path(self):
        executable = self.chrome_event(
            path=str(triage_daemon.Path.home())
            + "/Library/Application Support/Google/Chrome/payload.sh"
        )

        self.assertIsNone(
            triage_daemon.deterministic_maintenance_score(executable)
        )

    def test_deduplicate_collapses_duplicates_inside_same_batch(self):
        event = self.chrome_event()
        unique, skipped = triage_daemon.deduplicate([event, dict(event)])

        self.assertEqual(len(unique), 1)
        self.assertEqual(skipped, 1)

    def test_edr_skips_routine_data_but_scans_executable_write(self):
        with tempfile.TemporaryDirectory() as directory:
            data_file = os.path.join(directory, "browser.store")
            executable = os.path.join(directory, "payload.sh")
            with open(data_file, "w") as handle:
                handle.write("data")
            with open(executable, "w") as handle:
                handle.write("#!/bin/sh\n")

            base = {
                "source": "filemonitor",
                "event_type": "file_write",
            }
            self.assertFalse(
                triage_daemon.should_scan_file_with_edr(
                    {**base, "path": data_file}
                )
            )
            self.assertTrue(
                triage_daemon.should_scan_file_with_edr(
                    {**base, "path": executable}
                )
            )


class FalsePositiveExceptionTests(unittest.TestCase):
    def lulu_event(self, **overrides):
        event = {
            "source": "filemonitor",
            "event_type": "file_write",
            "path": "/Library/Objective-See/LuLu/rules.plist.sb-test",
            "process": (
                "/Library/SystemExtensions/UUID/"
                "com.objective-see.lulu.extension.systemextension/Contents/"
                "MacOS/com.objective-see.lulu.extension"
            ),
            "signing_status": "signed",
            "raw": {
                "file": {
                    "process": {
                        "name": "com.objective-see.lulu.extension",
                        "signing info (computed)": {
                            "teamID": "VBG97UB4TA",
                            "signatureID": "com.objective-see.lulu.extension",
                        },
                    },
                },
            },
        }
        event.update(overrides)
        return event

    def test_validated_lulu_self_write_matches_exception(self):
        rule = false_positive_exceptions.match_event(self.lulu_event())

        self.assertEqual(
            rule["id"], "objective-see-lulu-atomic-rules-write"
        )
        score = triage_daemon.deterministic_maintenance_score(
            self.lulu_event()
        )
        self.assertTrue(score["false_positive_exception"])
        self.assertEqual(score["risk_score"], 1)

    def test_unsigned_or_cross_process_lulu_write_does_not_match(self):
        unsigned = self.lulu_event(signing_status="unsigned")
        cross_process = self.lulu_event(process="/tmp/lulu-lookalike")

        self.assertIsNone(
            false_positive_exceptions.match_event(unsigned)
        )
        self.assertIsNone(
            false_positive_exceptions.match_event(cross_process)
        )

    def test_validated_google_updater_self_write_matches_exception(self):
        event = {
            "source": "filemonitor",
            "event_type": "file_create",
            "path": (
                str(triage_daemon.Path.home())
                + "/Library/Application Support/Google/GoogleUpdater/"
                + ".com.google.GoogleUpdater.test"
            ),
            "process": (
                str(triage_daemon.Path.home())
                + "/Library/Application Support/Google/GoogleUpdater/"
                + "144.0.7547.0/GoogleUpdater.app/Contents/MacOS/GoogleUpdater"
            ),
            "signing_status": "signed",
            "raw": {
                "file": {
                    "process": {
                        "name": "GoogleUpdater",
                        "signing info (computed)": {
                            "teamID": "EQHXZ8M8AV",
                            "signatureID": "com.google.GoogleUpdater",
                        },
                    },
                },
            },
        }

        rule = false_positive_exceptions.match_event(event)

        self.assertEqual(rule["id"], "google-updater-atomic-self-write")
        wrong_team = json.loads(json.dumps(event))
        wrong_team["raw"]["file"]["process"][
            "signing info (computed)"
        ]["teamID"] = "ATTACKER"
        self.assertIsNone(
            false_positive_exceptions.match_event(wrong_team)
        )

    def test_expired_rule_does_not_match(self):
        rules = [{
            "id": "expired",
            "enabled": True,
            "source": "filemonitor",
            "event_types": ["file_write"],
            "process_suffix": "com.objective-see.lulu.extension",
            "path_prefix": "/Library/Objective-See/LuLu/rules.plist.sb-",
            "signing_status": "signed",
            "team_id": "VBG97UB4TA",
            "signing_id": "com.objective-see.lulu.extension",
            "reason": "test",
            "expires_at": "2026-01-01T00:00:00Z",
        }]

        self.assertIsNone(false_positive_exceptions.match_event(
            self.lulu_event(),
            rules=rules,
            now=datetime(2026, 7, 27, tzinfo=timezone.utc),
        ))

    def test_broad_rule_is_rejected(self):
        errors = false_positive_exceptions.validate_rule({
            "id": "too-broad",
            "reason": "test",
            "source": "filemonitor",
            "event_types": ["file_write"],
        })

        self.assertIn(
            "at least one process identity constraint is required", errors
        )
        self.assertIn(
            "at least one destination constraint is required", errors
        )

    def test_audit_record_retains_event_and_rule(self):
        event = self.lulu_event()
        rule = false_positive_exceptions.match_event(event)
        score = false_positive_exceptions.exception_score(rule)

        with tempfile.TemporaryDirectory() as directory:
            audit_path = triage_daemon.Path(directory) / "audit.jsonl"
            false_positive_exceptions.append_audit(
                event, score, path=audit_path
            )
            record = json.loads(audit_path.read_text())

        self.assertEqual(
            record["rule_id"], "objective-see-lulu-atomic-rules-write"
        )
        self.assertEqual(record["event"]["path"], event["path"])


class HashLookupResilienceTests(unittest.TestCase):
    @patch.object(hash_lookup.requests.Session, "post")
    def test_404_disables_remote_lookup_for_current_client(self, post):
        response = Mock(status_code=404)
        post.return_value = response
        cache = Mock()
        cache.get.return_value = None
        client = hash_lookup.MalwareBazaarLookup(cache=cache)

        self.assertIsNone(client.lookup_sha256("a" * 64))
        self.assertIsNone(client.lookup_sha256("b" * 64))

        self.assertFalse(client.api_available)
        post.assert_called_once()


if __name__ == "__main__":
    unittest.main()
