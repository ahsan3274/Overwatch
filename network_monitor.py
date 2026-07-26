#!/usr/bin/env python3
"""
Overwatch Network Monitor v2
Monitors network connections for malware-like behavior
Enhanced with threat intelligence signatures
"""

import json
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import subprocess
import time
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
from typing import Optional, Dict, List

# Configuration
QUEUE_FILE = Path.home() / 'velociraptor-triage' / 'event_queue.jsonl'
LOG_FILE = Path.home() / 'velociraptor-triage' / 'network_monitor.log'
POLL_INTERVAL = 30

# ============================================
# TRUSTED PROCESSES (Reduce false positives)
# ============================================
TRUSTED_PROCESSES = {
    'com.apple', 'parsecd', 'Brave', 'Firefox', 'Chrome', 'Safari',
    'syncthing', 'Little Snitch', 'WindowServer', 'configd', 'mDNSResponder',
    'networkd', 'trustd', 'ocspd', 'apsd', 'cloudd', 'bird', 'UserEventAgent',
    'syslogd', 'logd', 'fseventsd', 'timequotad', 'thermalmonitord', 'powerd',
    # lsof truncates process names; these are verified local applications/services.
    'mullvadbr', 'OpenVPN', 'itunesclo', 'storekita', 'Obsidian', 'codex',
    'LM Studio'
}

# ============================================
# THREAT SIGNATURES - C2/Backdoor Ports
# ============================================
C2_PORTS = {
    4444: 'Metasploit default',
    5555: 'Android ADB (potential abuse)',
    6666: 'IRC backdoor',
    7777: 'Portainer/CLI backdoor',
    8888: 'HTTP alt (suspicious if non-browser)',
    9999: 'Rustdesk/remote access trojan',
    1337: 'Elite hacker port',
    31337: 'Back Orifice',
    54321: 'NetBus trojan',
    12345: 'NetBus trojan variant',
    20034: 'NetBus trojan',
    1243: 'SubSeven trojan',
    27374: 'SubSeven trojan',
    5800: 'VNC (unauthorized)',
    5900: 'VNC (unauthorized)',
}

# ============================================
# THREAT SIGNATURES - Cryptominer Ports
# ============================================
MINER_PORTS = {
    3333: 'NiceHash/Stratum mining',
    4444: 'Nanopool mining',
    5555: 'Mining pool',
    7777: 'Mining pool',
    8888: 'Mining pool',
    9999: 'Mining pool',
    14444: 'NiceHash mining',
    45560: 'NiceHash mining',
    48899: 'Monero mining pool',
    55555: 'Monero mining pool',
    7778: 'Monero mining pool',
    8333: 'Bitcoin mining pool',
    9333: 'Bitcoin mining pool',
}

# ============================================
# THREAT SIGNATURES - Suspicious Domains/IPs
# ============================================
SUSPICIOUS_DOMAIN_PATTERNS = [
    'pool.',      # Mining pools
    'xmr.',       # Monero mining
    'cryptonight',
    'stratum+tcp',
    'minexmr',
    'nanopool',
    'nicehash',
    'minergate',
    'coinhive',
    'webassembly.mining',
]

# Known C2 IP ranges (update from OSINT)
SUSPICIOUS_IP_RANGES = [
    '185.220.101.',  # Known C2 hosting
    '185.220.102.',  # Tor exit nodes (potential C2)
    '23.129.64.',    # Known malicious hosting
    '104.244.',      # Suspicious cloud
]

# ============================================
# Beaconing Detection
# ============================================
BEACON_THRESHOLD = 12  # New connections by one process to one IP in 5 minutes
BEACON_WINDOW = timedelta(minutes=5)

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


class NetworkMonitor:
    def __init__(self):
        self.connection_history = defaultdict(list)
        self.alerted_beacons = set()
        self.active_connections = set()

    def get_active_connections(self):
        try:
            result = subprocess.run(
                ['/usr/sbin/lsof', '-i', '-n', '-P'],
                capture_output=True,
                text=True,
                timeout=10
            )

            connections = []
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) < 9:
                    continue
                try:
                    conn = {
                        'process': parts[0],
                        'pid': int(parts[1]),
                        'user': parts[2],
                        'type': parts[3],
                        'protocol': parts[7].split('.')[0] if '.' in parts[7] else parts[7],
                        'remote_addr': self._parse_remote_addr(parts[8]),
                        'timestamp': datetime.now().isoformat()
                    }
                    if conn['remote_addr'] and conn['protocol'] in ('TCP', 'UDP'):
                        connections.append(conn)
                except (IndexError, ValueError):
                    continue
            return connections
        except Exception as e:
            log.error(f"Failed to get connections: {e}")
            return []

    def _parse_remote_addr(self, addr_str):
        try:
            if '->' in addr_str:
                remote = addr_str.split('->')[1].strip()
                if ':' in remote:
                    ip, port = remote.rsplit(':', 1)
                    return {'ip': ip, 'port': int(port), 'full': remote}
            elif ':' in addr_str and '(' not in addr_str:
                ip, port = addr_str.rsplit(':', 1)
                if ip not in ('*', ''):
                    return {'ip': ip, 'port': int(port), 'full': addr_str}
        except Exception:
            pass
        return None

    def is_trusted_process(self, process_name: str) -> bool:
        """Check if process is in trusted list"""
        for trusted in TRUSTED_PROCESSES:
            if trusted.lower() in process_name.lower():
                return True
        return False

    def check_c2_port(self, port: int) -> Optional[Dict]:
        """Check for known C2/backdoor ports"""
        if port in C2_PORTS:
            return {'port': port, 'reason': f'C2/Backdoor: {C2_PORTS[port]}', 'risk': 10}
        return None

    def check_miner_port(self, port: int) -> Optional[Dict]:
        """Check for cryptominer ports"""
        if port in MINER_PORTS:
            return {'port': port, 'reason': f'Cryptominer: {MINER_PORTS[port]}', 'risk': 9}
        return None

    def check_suspicious_domain(self, ip: str) -> Optional[Dict]:
        """Check IP against suspicious domain patterns"""
        try:
            result = subprocess.run(
                ['dig', '+short', '-x', ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            hostname = result.stdout.strip().lower()
            for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
                if pattern in hostname:
                    return {
                        'ip': ip,
                        'hostname': hostname,
                        'reason': f'Mining/C2 domain: {pattern}',
                        'risk': 10
                    }
        except Exception:
            pass
        return None

    def check_suspicious_ip(self, ip: str) -> Optional[Dict]:
        """Check IP against known-bad ranges"""
        for bad_range in SUSPICIOUS_IP_RANGES:
            if ip.startswith(bad_range):
                return {
                    'ip': ip,
                    'reason': f'Known malicious IP range: {bad_range}*',
                    'risk': 9
                }
        return None

    def detect_beaconing(self, conn: Dict) -> Optional[Dict]:
        """Detect repeated *new* connections, not repeated polls of one socket."""
        ip = conn['remote_addr']['ip']

        # Skip localhost and private IPs for beaconing
        try:
            if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
                return None
        except ValueError:
            return None

        now = datetime.now()
        history_key = (conn['process'].casefold(), conn['pid'], ip)
        self.connection_history[history_key].append(now)
        cutoff = now - BEACON_WINDOW
        self.connection_history[history_key] = [
            t for t in self.connection_history[history_key] if t > cutoff
        ]

        if len(self.connection_history[history_key]) >= BEACON_THRESHOLD:
            beacon_key = (*history_key, now.strftime('%Y%m%d_%H'))
            if beacon_key not in self.alerted_beacons:
                self.alerted_beacons.add(beacon_key)
                return {
                    'ip': ip,
                    'connections': len(self.connection_history[history_key]),
                    'window_minutes': BEACON_WINDOW.seconds // 60,
                    'reason': f'Possible beaconing: {len(self.connection_history[history_key])} new connections in {BEACON_WINDOW.seconds // 60} min',
                    # Timing frequency alone is not proof of C2.
                    'risk': 5
                }
        return None

    def calculate_risk_score(self, conn: Dict, checks: List[Dict]) -> int:
        """Calculate overall risk score (1-10)"""
        if not checks:
            return 1

        max_risk = max(check['risk'] for check in checks)

        # Boost score if multiple indicators
        if len(checks) >= 2:
            max_risk = min(10, max_risk + 1)
        if len(checks) >= 3:
            max_risk = min(10, max_risk + 1)

        return max_risk

    def create_event(self, conn: Dict, checks: List[Dict], risk_score: int) -> Dict:
        """Create Overwatch event for triage"""
        return {
            'source': 'network_monitor',
            'timestamp': datetime.now().isoformat(),
            'event_type': 'suspicious_network_connection',
            'process_name': conn['process'],
            'process_path': f"/proc/{conn['pid']}",
            'pid': conn['pid'],
            'user': conn['user'],
            'network': {
                'remote_ip': conn['remote_addr']['ip'],
                'remote_port': conn['remote_addr']['port'],
                'protocol': conn['protocol'],
            },
            'indicators': [check['reason'] for check in checks],
            'risk_score': risk_score,
            'flagged': risk_score >= 7,
            'raw_connection': conn
        }

    def write_to_queue(self, event: Dict):
        """Write event to Overwatch queue"""
        try:
            with open(QUEUE_FILE, 'a') as f:
                f.write(json.dumps(event) + '\n')
            log.info(f"Event: {event['network']['remote_ip']} (risk: {event['risk_score']})")
        except Exception as e:
            log.error(f"Failed to write to queue: {e}")

    def monitor_loop(self):
        """Main monitoring loop"""
        log.info("=== Overwatch Network Monitor v2 ===")
        log.info(f"Poll interval: {POLL_INTERVAL}s")
        log.info(f"Trusted processes: {len(TRUSTED_PROCESSES)}")
        log.info(f"C2 ports monitored: {len(C2_PORTS)}")
        log.info(f"Miner ports monitored: {len(MINER_PORTS)}")
        log.info(f"Suspicious IP ranges: {len(SUSPICIOUS_IP_RANGES)}")
        log.info(f"Queue file: {QUEUE_FILE}")

        while True:
            try:
                connections = self.get_active_connections()
                log.debug(f"Found {len(connections)} active connections")
                current_connections = set()

                for conn in connections:
                    if not conn.get('remote_addr'):
                        continue

                    # Skip trusted processes
                    if self.is_trusted_process(conn['process']):
                        continue

                    connection_key = (
                        conn['pid'], conn['type'], conn['protocol'],
                        conn['remote_addr']['full']
                    )
                    current_connections.add(connection_key)
                    is_new_connection = connection_key not in self.active_connections

                    # Run threat checks
                    checks = []

                    # Check 1: C2/Backdoor ports
                    c2_check = self.check_c2_port(conn['remote_addr']['port'])
                    if c2_check:
                        checks.append(c2_check)

                    # Check 2: Cryptominer ports
                    miner_check = self.check_miner_port(conn['remote_addr']['port'])
                    if miner_check:
                        checks.append(miner_check)

                    # Check 3: Suspicious IP ranges
                    ip_check = self.check_suspicious_ip(conn['remote_addr']['ip'])
                    if ip_check:
                        checks.append(ip_check)

                    # Check 4: Suspicious domains (reverse DNS)
                    domain_check = self.check_suspicious_domain(conn['remote_addr']['ip'])
                    if domain_check:
                        checks.append(domain_check)

                    # Check 5: Beaconing detection (C2 behavior)
                    beacon_check = self.detect_beaconing(conn) if is_new_connection else None
                    if beacon_check:
                        checks.append(beacon_check)

                    # Calculate risk and create event if suspicious
                    if checks:
                        risk_score = self.calculate_risk_score(conn, checks)
                        event = self.create_event(conn, checks, risk_score)
                        self.write_to_queue(event)

                        if risk_score >= 9:
                            log.warning(f"CRITICAL: {conn['process']} -> {conn['remote_addr']['full']} (risk: {risk_score})")

                self.active_connections = current_connections

                time.sleep(POLL_INTERVAL)

            except KeyboardInterrupt:
                log.info("Network Monitor stopped by user")
                break
            except Exception as e:
                log.error(f"Error in monitor loop: {e}")
                time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    monitor = NetworkMonitor()
    monitor.monitor_loop()
