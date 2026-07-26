#!/usr/bin/env python3
"""
Overwatch Process Watchdog
Audits configured Apple-process policy and integrates with Overwatch triage.
Enforcement is disabled unless OVERWATCH_WATCHDOG_ENFORCE is explicitly set.
"""

import json
import logging
from logging.handlers import RotatingFileHandler
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict

# Configuration
QUEUE_FILE = Path.home() / 'velociraptor-triage' / 'event_queue.jsonl'
LOG_FILE = Path.home() / 'velociraptor-triage' / 'process_watchdog.log'
POLL_INTERVAL = 60  # Check every 60 seconds
EVENT_COOLDOWN = 3600  # Do not queue the same policy result every minute
ENFORCEMENT_ENABLED = os.environ.get(
    'OVERWATCH_WATCHDOG_ENFORCE', ''
).casefold() in {'1', 'true', 'yes'}

# ============================================
# WATCHLIST - Processes to audit (or enforce only after explicit opt-in)
# ============================================
WATCHLIST = {
    # Siri/Spotlight (already disabled)
    'Assistantd': 'Siri voice assistant',
    'SiriNCService': 'Siri Notification Center',
    'parsecd': 'Spotlight/Siri suggestions',
    'CoreDuet': 'Behavior learning for Siri',
    'searchpartyd': 'Find My network',
    'suggestionsd': 'System suggestions',

    # iCloud
    'bird': 'iCloud Drive sync',
    'cloudd': 'iCloud services',
    'ProtectedCloudKeySyncing': 'iCloud Keychain sync',

    # Photos
    'PhotosReliveWidget': 'Photos memories widget',
    'photolibraryd': 'Photos library daemon',

    # Messages
    'MessagesAirlockService': 'Messages security',
    'CMFSyncAgent': 'Messages sync',

    # FaceTime
    'FTConversationService': 'FaceTime calls',

    # Weather/Stocks
    'WeatherIntents': 'Weather app intents',
    'WeatherWidget': 'Weather widget',
    'weatherd': 'Weather daemon',
    'StocksKitService': 'Stocks widget',

    # Game Center
    'gamed': 'Game Center daemon',
    'gamecontrollerd': 'Game controller support',
    'gamepolicyd': 'Game policy daemon',

    # AirPlay
    'AirPlayUIAgent': 'AirPlay UI',
    'AirPlayXPCHelper': 'AirPlay XPC',

    # Continuity
    'ContinuityCaptureAgent': 'Continuity camera',
    'syncdefaultsd': 'Sync defaults',
    'mapssyncd': 'Maps sync',

    # Telemetry
    'SubmitDiagInfo': 'Apple diagnostic reporting',
    'osanalyticshelper': 'OS analytics',

    # Time Machine
    'backupd': 'Time Machine backup',
}

# Launchd jobs to keep unloaded
LAUNCHD_JOBS = [
    '/System/Library/LaunchAgents/com.apple.backupd-auto.plist',
    '/System/Library/LaunchAgents/com.apple.bird.plist',
    '/System/Library/LaunchAgents/com.apple.cloudd.plist',
    '/System/Library/LaunchAgents/com.apple.icloud.fmfd.plist',
    '/System/Library/LaunchAgents/com.apple.photolibraryd.plist',
    '/System/Library/LaunchAgents/com.apple.MessagesAgent.plist',
    '/System/Library/LaunchAgents/com.apple.FaceTime.plist',
    '/System/Library/LaunchAgents/com.apple.gamed.plist',
    '/System/Library/LaunchAgents/com.apple.SubmitDiagInfo.plist',
    '/System/Library/LaunchAgents/com.apple.assistantd.plist',
    '/System/Library/LaunchAgents/com.apple.SiriNCService.plist',
    '/System/Library/LaunchAgents/com.apple.parsecd.plist',
    '/System/Library/LaunchAgents/com.apple.CoreDuetD.plist',
    '/System/Library/LaunchAgents/com.apple.searchpartyd.plist',
]

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


class ProcessWatchdog:
    def __init__(self, enforcement_enabled: bool = ENFORCEMENT_ENABLED):
        self.enforcement_enabled = enforcement_enabled
        self.killed_counts = {name: 0 for name in WATCHLIST.keys()}
        self.last_event_signature = None
        self.last_event_time = 0.0

    def check_running_processes(self) -> List[Dict]:
        """Check which watchlisted processes are running"""
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=10
            )

            violations = []
            for line in result.stdout.split('\n'):
                # Skip header line and empty lines
                if line.startswith('USER') or not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 11:
                    continue

                try:
                    process_name = parts[10].split('/')[-1]
                    pid = int(parts[1])
                    user = parts[0]

                    # Check if process is in watchlist
                    for watch_name, description in WATCHLIST.items():
                        if watch_name.casefold() == process_name.casefold():
                            violations.append({
                                'process': process_name,
                                'pid': pid,
                                'user': user,
                                'watchlist_name': watch_name,
                                'description': description,
                                'timestamp': datetime.now().isoformat()
                            })
                            break
                except (ValueError, IndexError):
                    continue

            return violations

        except Exception as e:
            log.error(f"Failed to check processes: {e}")
            return []

    def kill_process(self, pid: int, name: str) -> bool:
        """Terminate a specific process when enforcement is explicitly enabled."""
        if not self.enforcement_enabled:
            log.info(f"Audit-only: would terminate {name} (PID: {pid})")
            return False
        try:
            result = subprocess.run(
                ['kill', '-TERM', str(pid)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                detail = result.stderr.strip() or f"exit status {result.returncode}"
                log.warning(f"Could not kill {name} (PID: {pid}): {detail}")
                return False
            log.info(f"Killed process: {name} (PID: {pid})")
            return True
        except Exception as e:
            log.error(f"Failed to kill {name} (PID: {pid}): {e}")
            return False

    def unload_launchd_job(self, plist_path: str) -> bool:
        """Unload a launchd job when enforcement is explicitly enabled."""
        if not self.enforcement_enabled:
            log.info(f"Audit-only: would unload launchd job {plist_path}")
            return False
        try:
            result = subprocess.run(
                ['launchctl', 'unload', plist_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return False
            log.info(f"Unloaded launchd job: {plist_path}")
            return True
        except Exception as e:
            log.debug(f"Failed to unload {plist_path}: {e}")
            return False

    def create_event(self, violations: List[Dict]) -> Dict:
        """Create Overwatch event for triage"""
        return {
            'source': 'process_watchdog',
            'timestamp': datetime.now().isoformat(),
            'event_type': 'policy_enforcement',
            'violations': violations,
            'total_violations': len(violations),
            'risk_score': 1,
            'flagged': False,
            'expected_policy_enforcement': True,
            'enforcement_enabled': self.enforcement_enabled,
            'action_taken': (
                'Configured privacy-policy enforcement attempted'
                if self.enforcement_enabled
                else 'Audit only; no process or launchd changes attempted'
            )
        }

    def write_to_queue(self, event: Dict):
        """Write a rate-limited informational policy event to Overwatch."""
        signature = tuple(sorted(v['watchlist_name'] for v in event['violations']))
        now = time.time()
        if signature == self.last_event_signature and now - self.last_event_time < EVENT_COOLDOWN:
            log.debug("Suppressing repeated policy event during cooldown")
            return
        try:
            with open(QUEUE_FILE, 'a') as f:
                f.write(json.dumps(event) + '\n')
            self.last_event_signature = signature
            self.last_event_time = now
            log.info(f"Event written to queue: {event['total_violations']} violations")
        except Exception as e:
            log.error(f"Failed to write to queue: {e}")

    def enforce_policy(self):
        """Main enforcement loop"""
        log.info("=== Overwatch Process Watchdog ===")
        log.info(f"Watchlist: {len(WATCHLIST)} processes")
        log.info(f"Launchd jobs: {len(LAUNCHD_JOBS)} jobs")
        log.info(f"Poll interval: {POLL_INTERVAL}s")
        log.info(f"Queue file: {QUEUE_FILE}")
        log.info(
            "Mode: %s",
            "ENFORCING" if self.enforcement_enabled else "AUDIT ONLY"
        )

        while True:
            try:
                # Check for violations
                violations = self.check_running_processes()

                if violations:
                    log.warning(f"Found {len(violations)} watchlisted processes")

                    if self.enforcement_enabled:
                        # Enforce only after an operator explicitly opts in.
                        for v in violations:
                            if self.kill_process(v['pid'], v['watchlist_name']):
                                self.killed_counts[v['watchlist_name']] += 1

                        for job in LAUNCHD_JOBS:
                            self.unload_launchd_job(job)
                    else:
                        log.info(
                            "Audit-only mode: no processes or launchd jobs changed"
                        )

                    # Create event for triage
                    event = self.create_event(violations)
                    self.write_to_queue(event)

                    if self.enforcement_enabled and len(violations) >= 3:
                        log.info(
                            f"Policy enforcement attempted for {len(violations)} configured processes"
                        )

                else:
                    log.debug("No violations found")

                time.sleep(POLL_INTERVAL)

            except KeyboardInterrupt:
                log.info("Process Watchdog stopped by user")
                break
            except Exception as e:
                log.error(f"Error in enforcement loop: {e}")
                time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    watchdog = ProcessWatchdog()
    watchdog.enforce_policy()
