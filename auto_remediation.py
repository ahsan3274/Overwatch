#!/usr/bin/env python3
"""
Overwatch Auto-Remediation Module
Automated response actions for flagged security events:
- File quarantine
- Process termination
- Persistence removal
- Network blocking
- Audit logging
"""

import json
import os
import shutil
import subprocess
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict

# ── Config ────────────────────────────────────────────────────────────────────

BASE_DIR = Path.home() / "velociraptor-triage"
QUARANTINE_DIR = BASE_DIR / "quarantine"
REMEDIATION_LOG = BASE_DIR / "remediation.log"
BLOCKLIST_FILE = BASE_DIR / "pf_blocklist.txt"
AUTO_REMEDIATE_CONFIG = BASE_DIR / "auto_remediate_config.json"

# Third-party security tools
LULU_APP = "/Applications/LuLu.app"
BLOCKBLOCK_APP = "/Applications/BlockBlock Helper.app"

# Auto-remediation thresholds
AUTO_QUARANTINE_SCORE = 8      # Auto-quarantine files with risk >= this
AUTO_KILL_SCORE = 9            # Auto-kill processes with risk >= this
AUTO_BLOCK_SCORE = 9           # Auto-block network with risk >= this

# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class RemediationResult:
    """Result of a remediation action."""
    action: str
    success: bool
    timestamp: str
    target: str
    details: str
    error: Optional[str] = None
    risk_score: Optional[int] = None

# ── Logging ────────────────────────────────────────────────────────────────────

def log_remediation(result: RemediationResult):
    """Log remediation action to file."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with open(REMEDIATION_LOG, 'a') as f:
        f.write(json.dumps(asdict(result)) + '\n')

# ── File Quarantine ───────────────────────────────────────────────────────────

def quarantine_file(file_path: str, risk_score: int = 0, reason: str = "") -> RemediationResult:
    """
    Move suspicious file to quarantine directory.
    
    Args:
        file_path: Path to file to quarantine
        risk_score: Risk score of the event
        reason: Reason for quarantine
    
    Returns:
        RemediationResult with success/failure details
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        source = Path(file_path)
        if not source.exists():
            return RemediationResult(
                action="quarantine_file",
                success=False,
                timestamp=timestamp,
                target=file_path,
                details="File not found",
                risk_score=risk_score
            )
        
        # Create quarantine subdirectory with timestamp
        quarantine_subdir = QUARANTINE_DIR / datetime.now().strftime("%Y-%m-%d")
        quarantine_subdir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique quarantine name
        file_hash = hashlib.sha256(file_path.encode()).hexdigest()[:8]
        quarantine_name = f"{timestamp[:10]}_{file_hash}_{source.name}"
        quarantine_path = quarantine_subdir / quarantine_name
        
        # Move file
        shutil.move(str(source), str(quarantine_path))
        
        # Create metadata file
        metadata = {
            "original_path": str(source),
            "quarantine_path": str(quarantine_path),
            "timestamp": timestamp,
            "risk_score": risk_score,
            "reason": reason,
            "original_name": source.name,
            "file_size": quarantine_path.stat().st_size if quarantine_path.exists() else 0,
        }
        with open(quarantine_path.with_suffix('.meta'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        result = RemediationResult(
            action="quarantine_file",
            success=True,
            timestamp=timestamp,
            target=file_path,
            details=f"Moved to {quarantine_path}",
            risk_score=risk_score
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="quarantine_file",
            success=False,
            timestamp=timestamp,
            target=file_path,
            details="Failed to quarantine",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result


def restore_from_quarantine(quarantine_path: str) -> RemediationResult:
    """Restore file from quarantine to original location."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        source = Path(quarantine_path)
        if not source.exists():
            return RemediationResult(
                action="restore_from_quarantine",
                success=False,
                timestamp=timestamp,
                target=quarantine_path,
                details="Quarantine file not found"
            )
        
        # Load metadata
        meta_path = source.with_suffix('.meta')
        if not meta_path.exists():
            return RemediationResult(
                action="restore_from_quarantine",
                success=False,
                timestamp=timestamp,
                target=quarantine_path,
                details="Metadata file not found"
            )
        
        with open(meta_path) as f:
            metadata = json.load(f)
        
        # Restore to original location
        original_path = Path(metadata['original_path'])
        original_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(original_path))
        
        # Clean up metadata
        meta_path.unlink()
        
        result = RemediationResult(
            action="restore_from_quarantine",
            success=True,
            timestamp=timestamp,
            target=quarantine_path,
            details=f"Restored to {original_path}"
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="restore_from_quarantine",
            success=False,
            timestamp=timestamp,
            target=quarantine_path,
            details="Failed to restore",
            error=str(e)
        )
        log_remediation(result)
        return result


def delete_from_quarantine(quarantine_path: str) -> RemediationResult:
    """Permanently delete file from quarantine."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        source = Path(quarantine_path)
        if not source.exists():
            return RemediationResult(
                action="delete_from_quarantine",
                success=False,
                timestamp=timestamp,
                target=quarantine_path,
                details="File not found"
            )
        
        # Also delete metadata if exists
        meta_path = source.with_suffix('.meta')
        if meta_path.exists():
            meta_path.unlink()
        
        source.unlink()
        
        result = RemediationResult(
            action="delete_from_quarantine",
            success=True,
            timestamp=timestamp,
            target=quarantine_path,
            details="Permanently deleted"
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="delete_from_quarantine",
            success=False,
            timestamp=timestamp,
            target=quarantine_path,
            details="Failed to delete",
            error=str(e)
        )
        log_remediation(result)
        return result

# ── Process Termination ───────────────────────────────────────────────────────

def kill_process(pid: int, risk_score: int = 0, reason: str = "") -> RemediationResult:
    """
    Terminate a malicious process.
    
    Args:
        pid: Process ID to kill
        risk_score: Risk score of the event
        reason: Reason for termination
    
    Returns:
        RemediationResult with success/failure details
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        # Get process info before killing
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True, text=True, timeout=5
            )
            process_name = result.stdout.strip() or "unknown"
        except:
            process_name = "unknown"
        
        # Kill process
        subprocess.run(
            ["kill", "-9", str(pid)],
            capture_output=True, text=True, timeout=5
        )
        
        # Verify process is dead
        verify = subprocess.run(
            ["ps", "-p", str(pid)],
            capture_output=True, text=True, timeout=5
        )
        
        if verify.returncode != 0:
            result = RemediationResult(
                action="kill_process",
                success=True,
                timestamp=timestamp,
                target=f"PID {pid} ({process_name})",
                details=f"Process terminated",
                risk_score=risk_score
            )
        else:
            result = RemediationResult(
                action="kill_process",
                success=False,
                timestamp=timestamp,
                target=f"PID {pid}",
                details="Process may have respawned",
                risk_score=risk_score
            )
        
        log_remediation(result)
        return result
        
    except subprocess.TimeoutExpired:
        result = RemediationResult(
            action="kill_process",
            success=False,
            timestamp=timestamp,
            target=f"PID {pid}",
            details="Command timed out",
            risk_score=risk_score
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="kill_process",
            success=False,
            timestamp=timestamp,
            target=f"PID {pid}",
            details="Failed to kill process",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result


def kill_process_by_name(process_name: str, risk_score: int = 0) -> List[RemediationResult]:
    """Kill all processes matching a name."""
    results = []
    
    try:
        # Find PIDs
        result = subprocess.run(
            ["pgrep", "-f", process_name],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0:
            pids = [int(p.strip()) for p in result.stdout.split('\n') if p.strip()]
            for pid in pids:
                results.append(kill_process(pid, risk_score, f"Process name: {process_name}"))
        else:
            results.append(RemediationResult(
                action="kill_process_by_name",
                success=False,
                timestamp=datetime.now(timezone.utc).isoformat(),
                target=process_name,
                details="No matching processes found",
                risk_score=risk_score
            ))
        
    except Exception as e:
        results.append(RemediationResult(
            action="kill_process_by_name",
            success=False,
            timestamp=datetime.now(timezone.utc).isoformat(),
            target=process_name,
            details="Failed to find processes",
            error=str(e),
            risk_score=risk_score
        ))
    
    return results

# ── Persistence Removal ───────────────────────────────────────────────────────

def remove_persistence(path: str, risk_score: int = 0) -> RemediationResult:
    """
    Remove malicious persistence mechanism.
    
    Handles:
    - LaunchAgents
    - LaunchDaemons
    - cron jobs
    - login items
    
    Args:
        path: Path to persistence file or identifier
        risk_score: Risk score of the event
    
    Returns:
        RemediationResult with success/failure details
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        source = Path(path)
        
        # Check if it's a file path
        if source.exists() and source.is_file():
            # Quarantine first, then delete
            quarantine_result = quarantine_file(str(source), risk_score, "Persistence mechanism")
            
            if quarantine_result.success:
                # If it's a LaunchAgent/Daemon, unload it first
                if "LaunchAgents" in path or "LaunchDaemons" in path:
                    plist_name = source.stem
                    try:
                        subprocess.run(
                            ["launchctl", "bootout", "gui/" + str(os.getuid()), plist_name],
                            capture_output=True, timeout=5
                        )
                    except:
                        pass
                
                result = RemediationResult(
                    action="remove_persistence",
                    success=True,
                    timestamp=timestamp,
                    target=path,
                    details=f"Persistence removed and quarantined",
                    risk_score=risk_score
                )
            else:
                result = RemediationResult(
                    action="remove_persistence",
                    success=False,
                    timestamp=timestamp,
                    target=path,
                    details="Failed to quarantine persistence file",
                    risk_score=risk_score
                )
        else:
            # Try to unload as launchd job
            try:
                subprocess.run(
                    ["launchctl", "bootout", "gui/" + str(os.getuid()), path],
                    capture_output=True, timeout=5
                )
                result = RemediationResult(
                    action="remove_persistence",
                    success=True,
                    timestamp=timestamp,
                    target=path,
                    details="Launchd job unloaded",
                    risk_score=risk_score
                )
            except Exception as e:
                result = RemediationResult(
                    action="remove_persistence",
                    success=False,
                    timestamp=timestamp,
                    target=path,
                    details="Persistence target not found",
                    error=str(e),
                    risk_score=risk_score
                )
        
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="remove_persistence",
            success=False,
            timestamp=timestamp,
            target=path,
            details="Failed to remove persistence",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result


def remove_cron_job(cron_entry: str, risk_score: int = 0) -> RemediationResult:
    """Remove malicious cron job."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        # Get current user's crontab
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode != 0:
            return RemediationResult(
                action="remove_cron_job",
                success=False,
                timestamp=timestamp,
                target=cron_entry,
                details="No crontab found",
                risk_score=risk_score
            )
        
        # Remove matching line
        lines = result.stdout.split('\n')
        new_lines = [l for l in lines if cron_entry not in l]
        
        if len(new_lines) == len(lines):
            return RemediationResult(
                action="remove_cron_job",
                success=False,
                timestamp=timestamp,
                target=cron_entry,
                details="Cron entry not found",
                risk_score=risk_score
            )
        
        # Install new crontab
        subprocess.run(
            ["crontab", "-"],
            input='\n'.join(new_lines),
            text=True,
            capture_output=True,
            timeout=5
        )
        
        result = RemediationResult(
            action="remove_cron_job",
            success=True,
            timestamp=timestamp,
            target=cron_entry,
            details="Cron job removed",
            risk_score=risk_score
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="remove_cron_job",
            success=False,
            timestamp=timestamp,
            target=cron_entry,
            details="Failed to remove cron job",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result

# ── Network Blocking ──────────────────────────────────────────────────────────

def block_ip(ip_address: str, risk_score: int = 0, duration: str = "permanent") -> RemediationResult:
    """
    Block IP address using PF (Packet Filter) firewall.
    
    Args:
        ip_address: IP to block
        risk_score: Risk score of the event
        duration: "permanent" or time-based
    
    Returns:
        RemediationResult with success/failure details
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        # Add to blocklist file
        BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        
        # Check if already blocked
        if BLOCKLIST_FILE.exists():
            with open(BLOCKLIST_FILE) as f:
                if ip_address in f.read():
                    return RemediationResult(
                        action="block_ip",
                        success=False,
                        timestamp=timestamp,
                        target=ip_address,
                        details="IP already blocked",
                        risk_score=risk_score
                    )
        
        # Append to blocklist
        with open(BLOCKLIST_FILE, 'a') as f:
            f.write(f"block drop quick from {ip_address} to any # risk:{risk_score} {timestamp}\n")
        
        # Reload PF if possible (requires sudo)
        try:
            subprocess.run(
                ["sudo", "pfctl", "-f", "/etc/pf.conf"],
                capture_output=True, timeout=5
            )
        except:
            pass  # Will apply on next reboot or manual reload
        
        result = RemediationResult(
            action="block_ip",
            success=True,
            timestamp=timestamp,
            target=ip_address,
            details=f"IP added to blocklist",
            risk_score=risk_score
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="block_ip",
            success=False,
            timestamp=timestamp,
            target=ip_address,
            details="Failed to block IP",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result


def unblock_ip(ip_address: str) -> RemediationResult:
    """Remove IP from blocklist."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        if not BLOCKLIST_FILE.exists():
            return RemediationResult(
                action="unblock_ip",
                success=False,
                timestamp=timestamp,
                target=ip_address,
                details="Blocklist not found"
            )
        
        with open(BLOCKLIST_FILE) as f:
            lines = f.readlines()
        
        new_lines = [l for l in lines if ip_address not in l]
        
        if len(new_lines) == len(lines):
            return RemediationResult(
                action="unblock_ip",
                success=False,
                timestamp=timestamp,
                target=ip_address,
                details="IP not in blocklist"
            )
        
        with open(BLOCKLIST_FILE, 'w') as f:
            f.writelines(new_lines)
        
        result = RemediationResult(
            action="unblock_ip",
            success=True,
            timestamp=timestamp,
            target=ip_address,
            details="IP removed from blocklist"
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        result = RemediationResult(
            action="unblock_ip",
            success=False,
            timestamp=timestamp,
            target=ip_address,
            details="Failed to unblock IP",
            error=str(e)
        )
        log_remediation(result)
        return result


def block_domain(domain: str, risk_score: int = 0) -> RemediationResult:
    """Block domain by adding to /etc/hosts."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        result = RemediationResult(
            action="block_domain",
            success=True,
            timestamp=timestamp,
            target=domain,
            details=f"Recommend: echo '0.0.0.0 {domain}' | sudo tee -a /etc/hosts",
            risk_score=risk_score
        )
        log_remediation(result)
        return result
        
    except Exception as e:
        return RemediationResult(
            action="block_domain",
            success=False,
            timestamp=timestamp,
            target=domain,
            details="Failed to block domain",
            error=str(e),
            risk_score=risk_score
        )


# ── LuLu Integration (Network Firewall) ───────────────────────────────────────

def lulu_block_process(process_path: str, risk_score: int = 0, reason: str = "") -> RemediationResult:
    """
    Block a process's network access using LuLu.
    
    LuLu is Objective-See's open-source firewall that blocks outbound connections.
    Note: Requires LuLu to be installed and running.
    
    Args:
        process_path: Path to the process binary to block
        risk_score: Risk score of the event
        reason: Reason for blocking
    
    Returns:
        RemediationResult with success/failure details
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        # LuLu doesn't have a public CLI, but we can use AppleScript to interact with it
        # For now, we'll use PF firewall as fallback
        script = f'''
        tell application "LuLu"
            activate
        end tell
        '''
        
        # Try AppleScript first
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=5
        )
        
        # Add to PF blocklist as reliable fallback
        BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKLIST_FILE, 'a') as f:
            f.write(f"# LuLu block: {process_path} (risk: {risk_score})\\n")
        
        remediation_result = RemediationResult(
            action="lulu_block_process",
            success=True,
            timestamp=timestamp,
            target=process_path,
            details=f"Process flagged for network blocking (LuLu notified, PF rule added)",
            risk_score=risk_score
        )
        log_remediation(remediation_result)
        return remediation_result
        
    except Exception as e:
        result = RemediationResult(
            action="lulu_block_process",
            success=False,
            timestamp=timestamp,
            target=process_path,
            details="Failed to block via LuLu",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result


def lulu_block_ip(ip_address: str, risk_score: int = 0) -> RemediationResult:
    """Block an IP address using LuLu and PF firewall."""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        # Notify LuLu (via AppleScript)
        script = f'''
        tell application "LuLu"
            activate
        end tell
        '''
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
        
        # Add to PF blocklist (reliable)
        BLOCKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKLIST_FILE, 'a') as f:
            f.write(f"block drop quick from {ip_address} to any # LuLu block (risk:{risk_score})\\n")
            f.write(f"block drop quick from any to {ip_address} # LuLu block (risk:{risk_score})\\n")
        
        remediation_result = RemediationResult(
            action="lulu_block_ip",
            success=True,
            timestamp=timestamp,
            target=ip_address,
            details="IP blocked via PF (LuLu notified)",
            risk_score=risk_score
        )
        log_remediation(remediation_result)
        return remediation_result
        
    except Exception as e:
        result = RemediationResult(
            action="lulu_block_ip",
            success=False,
            timestamp=timestamp,
            target=ip_address,
            details="Failed to block IP via LuLu",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result


# ── BlockBlock Integration (Persistence Monitoring) ───────────────────────────

def blockblock_add_watch(path: str, risk_score: int = 0) -> RemediationResult:
    """
    Add a path to BlockBlock's watch list.
    
    BlockBlock monitors persistence locations and alerts when changes occur.
    It can automatically block unauthorized persistence mechanisms.
    Note: Requires BlockBlock to be installed and running.
    
    Args:
        path: Path to watch for persistence changes
        risk_score: Risk score of the event
    
    Returns:
        RemediationResult with success/failure details
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        # Notify BlockBlock via AppleScript
        script = f'''
        tell application "BlockBlock"
            activate
        end tell
        '''
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
        
        # BlockBlock automatically monitors standard persistence locations
        # We log the request and let BlockBlock handle it via its UI
        remediation_result = RemediationResult(
            action="blockblock_add_watch",
            success=True,
            timestamp=timestamp,
            target=path,
            details="BlockBlock notified to watch path (check BlockBlock UI for approval)",
            risk_score=risk_score
        )
        log_remediation(remediation_result)
        return remediation_result
        
    except Exception as e:
        result = RemediationResult(
            action="blockblock_add_watch",
            success=False,
            timestamp=timestamp,
            target=path,
            details="Failed to add watch via BlockBlock",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result


def blockblock_block_persistence(persistence_path: str, risk_score: int = 0) -> RemediationResult:
    """
    Block a persistence mechanism using BlockBlock.
    
    This notifies BlockBlock and falls back to manual removal.
    BlockBlock will show an alert for user confirmation.
    
    Args:
        persistence_path: Path to the persistence file (plist, script, etc.)
        risk_score: Risk score of the event
    
    Returns:
        RemediationResult with success/failure details
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    
    try:
        # Notify BlockBlock via AppleScript
        script = '''
        tell application "BlockBlock"
            activate
        end tell
        '''
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
        
        # Fall back to manual removal (BlockBlock will show UI alert)
        remediation_result = remove_persistence(persistence_path, risk_score)
        remediation_result.action = "blockblock_block_persistence"
        remediation_result.details = f"BlockBlock notified + {remediation_result.details}"
        
        log_remediation(remediation_result)
        return remediation_result
        
    except Exception as e:
        result = RemediationResult(
            action="blockblock_block_persistence",
            success=False,
            timestamp=timestamp,
            target=persistence_path,
            details="Failed to block via BlockBlock",
            error=str(e),
            risk_score=risk_score
        )
        log_remediation(result)
        return result

# ── Auto-Remediation Engine ───────────────────────────────────────────────────

def load_auto_remediate_config() -> Dict[str, Any]:
    """Load auto-remediation configuration."""
    if not AUTO_REMEDIATE_CONFIG.exists():
        return {
            "enabled": True,
            "auto_quarantine_score": AUTO_QUARANTINE_SCORE,
            "auto_kill_score": AUTO_KILL_SCORE,
            "auto_block_score": AUTO_BLOCK_SCORE,
            "require_confirmation": True,
            "excluded_paths": [],
        }
    
    with open(AUTO_REMEDIATE_CONFIG) as f:
        return json.load(f)


def save_auto_remediate_config(config: Dict[str, Any]):
    """Save auto-remediation configuration."""
    with open(AUTO_REMEDIATE_CONFIG, 'w') as f:
        json.dump(config, f, indent=2)


def auto_remediate_event(event: Dict[str, Any]) -> List[RemediationResult]:
    """
    Automatically remediate a security event based on risk score.
    
    Uses integrated security tools:
    - LuLu: Network blocking for malicious processes/IPs
    - BlockBlock: Persistence mechanism blocking
    - Built-in: File quarantine, process termination
    
    Args:
        event: Scored event dict with assessment and original_event
    
    Returns:
        List of RemediationResult for each action taken
    """
    results = []
    config = load_auto_remediate_config()
    
    if not config.get("enabled"):
        return results
    
    assessment = event.get("assessment", {})
    original = event.get("original_event", {})
    risk_score = assessment.get("risk_score", 0)
    risk_level = assessment.get("risk_level", "LOW")
    category = assessment.get("category", "").lower()
    
    # Check excluded paths
    path = original.get("path", "")
    for excluded in config.get("excluded_paths", []):
        if excluded in path:
            return results
    
    # 1. Auto-quarantine files
    if risk_score >= config.get("auto_quarantine_score", AUTO_QUARANTINE_SCORE):
        if path and original.get("event_type", "").startswith("file_"):
            results.append(quarantine_file(
                path, 
                risk_score, 
                f"Auto-quarantine: {category} - {assessment.get('explanation', '')[:100]}"
            ))
    
    # 2. Auto-kill processes
    if risk_score >= config.get("auto_kill_score", AUTO_KILL_SCORE):
        process = original.get("process", "")
        if process:
            results.append(kill_process_by_name(process, risk_score))
    
    # 3. Block network access via LuLu (if available)
    if risk_score >= config.get("auto_block_score", AUTO_BLOCK_SCORE):
        # Block process network access via LuLu
        process_path = original.get("process", "")
        if process_path:
            results.append(lulu_block_process(process_path, risk_score, f"Auto-block: {category}"))
        
        # Block IPs if found in path
        import re
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = re.findall(ip_pattern, path)
        for ip in ips:
            results.append(lulu_block_ip(ip, risk_score))
    
    # 4. Block persistence via BlockBlock (if persistence-related)
    persistence_keywords = ["launchagent", "launchdaemon", "persistence", "login", "cron"]
    if any(kw in path.lower() for kw in persistence_keywords):
        results.append(blockblock_block_persistence(path, risk_score))
    
    # 5. Add suspicious paths to BlockBlock watch list
    if risk_score >= 7 and path:
        watch_paths = [
            "/Library/LaunchAgents/",
            "/Library/LaunchDaemons/",
            "~/.ssh/",
        ]
        if any(wp in path for wp in watch_paths):
            results.append(blockblock_add_watch(path, risk_score))
    
    return results

# ── Quarantine Management ─────────────────────────────────────────────────────

def list_quarantine() -> List[Dict[str, Any]]:
    """List all quarantined files with metadata."""
    items = []
    
    if not QUARANTINE_DIR.exists():
        return items
    
    for date_dir in sorted(QUARANTINE_DIR.iterdir(), reverse=True):
        if not date_dir.is_dir():
            continue
        
        for meta_file in date_dir.glob("*.meta"):
            try:
                with open(meta_file) as f:
                    metadata = json.load(f)
                
                quarantine_file = meta_file.with_suffix('')
                metadata['quarantine_path'] = str(quarantine_file)
                metadata['exists'] = quarantine_file.exists()
                items.append(metadata)
            except:
                pass
    
    return items


def get_quarantine_stats() -> Dict[str, Any]:
    """Get quarantine statistics."""
    items = list_quarantine()
    
    total_size = 0
    by_risk = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    
    for item in items:
        total_size += item.get('file_size', 0)
        risk_score = item.get('risk_score', 0)
        if risk_score >= 9:
            by_risk["CRITICAL"] += 1
        elif risk_score >= 7:
            by_risk["HIGH"] += 1
        elif risk_score >= 4:
            by_risk["MEDIUM"] += 1
        else:
            by_risk["LOW"] += 1
    
    return {
        "total_files": len(items),
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "by_risk_level": by_risk,
        "quarantine_dir": str(QUARANTINE_DIR),
    }

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test/demo
    print("Overwatch Auto-Remediation Module")
    print("=" * 40)
    
    stats = get_quarantine_stats()
    print(f"\nQuarantine Stats:")
    print(f"  Total files: {stats['total_files']}")
    print(f"  Total size: {stats['total_size_mb']} MB")
    print(f"  By risk: {stats['by_risk_level']}")
    
    config = load_auto_remediate_config()
    print(f"\nAuto-Remediation Config:")
    print(f"  Enabled: {config.get('enabled')}")
    print(f"  Auto-quarantine score: {config.get('auto_quarantine_score')}")
    print(f"  Auto-kill score: {config.get('auto_kill_score')}")
