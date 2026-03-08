#!/usr/bin/env python3
"""
OSINT Ingester for Overwatch
Extracts cybersecurity intelligence from OSINT Reporter output,
compresses it into actionable context, and feeds it to the triage model.

Key features:
- Filters only cybersecurity/tech content (ignores geopolitics, finance)
- Rolling window (last 24-72 hours) to prevent prompt explosion
- Intelligent compression (group by threat type, deduplicate)
- Provides structured context for AI triage
"""

import json
import os
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

# ── Config ────────────────────────────────────────────────────────────────────

OSINT_OUTPUT_DIR = Path.home() / "osint-reporter" / "output"
INTEL_DIR = OSINT_OUTPUT_DIR / "intelligence"
BASE_DIR = Path.home() / "velociraptor-triage"
OSINT_CACHE = BASE_DIR / "osint_context.json"
OSINT_STATE = BASE_DIR / "osint_state.json"

# Rolling window: how far back to look for intel
INTEL_WINDOW_HOURS = 48  # Last 48 hours of threat intel

# Compression settings
MAX_INTEL_ITEMS = 20     # Max individual threat items to include
MAX_CVE_COUNT = 10       # Max CVEs to list explicitly
MAX_TOKENS_ESTIMATE = 2000  # Target max token count for context

# Categories to include (ignore geopolitics, finance, etc.)
RELEVANT_CATEGORIES = {"cybersecurity", "tech_ai"}

# ── Helpers ───────────────────────────────────────────────────────────────────


def get_utc_now() -> datetime:
    """Get current UTC time."""
    return datetime.now(timezone.utc)


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime."""
    if not ts_str:
        return None
    try:
        # Handle various ISO formats
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None


def is_within_window(ts: datetime, window_hours: int = INTEL_WINDOW_HOURS) -> bool:
    """Check if timestamp is within the rolling window."""
    if not ts:
        return False
    cutoff = get_utc_now() - timedelta(hours=window_hours)
    return ts >= cutoff


def event_hash(event: dict) -> str:
    """Create unique hash for deduplication."""
    key = f"{event.get('title', '')}{event.get('url', '')}{event.get('published', '')}"
    return hashlib.md5(key.encode()).hexdigest()


# ── OSINT Loaders ─────────────────────────────────────────────────────────────


def load_latest_intel() -> Optional[dict]:
    """Load the latest intelligence report."""
    if not INTEL_DIR.exists():
        return None
    
    # Try latest_intel.json first
    latest_file = INTEL_DIR / "latest_intel.json"
    if latest_file.exists():
        try:
            with open(latest_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    
    # Fall back to most recent intel_*.json
    intel_files = sorted(INTEL_DIR.glob("intel_*.json"), reverse=True)
    if intel_files:
        try:
            with open(intel_files[0]) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    
    return None


def load_collected_events() -> list[dict]:
    """Load collected cybersecurity events from most recent report."""
    if not OSINT_OUTPUT_DIR.exists():
        return []
    
    # Find most recent collected_*.json
    collected_files = sorted(OSINT_OUTPUT_DIR.glob("collected_*.json"), reverse=True)
    if not collected_files:
        return []
    
    try:
        with open(collected_files[0]) as f:
            data = json.load(f)
            # Extract only cybersecurity category
            cyber_events = data.get("cybersecurity", [])
            return cyber_events
    except (json.JSONDecodeError, IOError):
        return []


# ── Intelligence Extractor ────────────────────────────────────────────────────


def extract_threat_landscape(intel: dict) -> dict:
    """
    Extract threat landscape from intelligence report.
    Returns structured threat intel, not raw text.
    """
    summary = intel.get("summary", {})
    executive_brief = summary.get("executive_brief", "")
    
    # Parse executive brief for threat sections
    threats = {
        "apt_campaigns": [],
        "active_cves": [],
        "malware_families": [],
        "threat_actors": [],
        "attack_techniques": [],
    }
    
    # Extract key threat intel from brief
    # Look for patterns like "APT28", "CVE-2025", "Transparent Tribe"
    import re
    
    # APT groups
    apt_pattern = r"(APT\d+|[A-Z][a-z]+ (?:Tribe|Spider|Bear|Lazarus|Cobalt))"
    threats["threat_actors"] = list(set(re.findall(apt_pattern, executive_brief)))
    
    # CVEs
    cve_pattern = r"(CVE-\d{4}-\d+)"
    threats["active_cves"] = list(set(re.findall(cve_pattern, executive_brief)))[:MAX_CVE_COUNT]
    
    # Malware
    malware_pattern = r"(?:malware|implant|tooling|RAT|backdoor|stealer)[:\s]*([A-Z][a-zA-Z0-9]+)"
    threats["malware_families"] = list(set(re.findall(malware_pattern, executive_brief)))
    
    return threats


def filter_cyber_events(events: list[dict], limit: int = MAX_INTEL_ITEMS) -> list[dict]:
    """
    Filter and rank cybersecurity events.
    Returns top events within the time window.
    """
    now = get_utc_now()
    filtered = []
    
    for event in events:
        # Check if within time window
        published = parse_timestamp(event.get("published", ""))
        if not is_within_window(published, INTEL_WINDOW_HOURS):
            continue
        
        # Score event by relevance
        score = 0
        
        # CVE mentions = high priority
        if "CVE-" in event.get("title", "") or "CVE-" in event.get("summary", ""):
            score += 10
        
        # Exploit/vulnerability keywords
        exploit_keywords = ["exploit", "vulnerability", "bypass", "RCE", "LPE", "zero-day"]
        title_lower = event.get("title", "").lower()
        summary_lower = event.get("summary", "").lower()
        if any(kw in title_lower or kw in summary_lower for kw in exploit_keywords):
            score += 5
        
        # APT/threat actor mentions
        apt_keywords = ["APT", "threat actor", "campaign", "attribution"]
        if any(kw in title_lower or kw in summary_lower for kw in apt_keywords):
            score += 8
        
        # Auth bypass / credential issues
        if "auth" in title_lower or "credential" in title_lower or "bypass" in title_lower:
            score += 7
        
        # Add to filtered list
        filtered.append({
            **event,
            "_relevance_score": score,
            "_published_dt": published,
        })
    
    # Sort by relevance and recency
    filtered.sort(key=lambda x: (x["_relevance_score"], x.get("_published_dt") or now), reverse=True)
    
    # Return top N, removing internal fields
    result = []
    for item in filtered[:limit]:
        clean = {k: v for k, v in item.items() if not k.startswith("_")}
        result.append(clean)
    
    return result


# ── Context Builder ───────────────────────────────────────────────────────────


def build_osint_context() -> dict:
    """
    Build compressed OSINT context for triage model.
    
    Returns a structured dict with:
    - threat_landscape: APT groups, active CVEs, malware families
    - top_events: Most relevant cybersecurity events
    - summary: One-paragraph threat overview
    - generated_at: Timestamp
    """
    # Load intel sources
    intel = load_latest_intel()
    cyber_events = load_collected_events()
    
    if not intel and not cyber_events:
        return {
            "available": False,
            "message": "No OSINT data available",
        }
    
    # Extract threat landscape
    threats = extract_threat_landscape(intel) if intel else {}
    
    # Filter cyber events
    top_events = filter_cyber_events(cyber_events)
    
    # Build executive summary from intel
    summary_text = ""
    if intel:
        brief = intel.get("summary", {}).get("executive_brief", "")
        # Extract just the THREAT LANDSCAPE section
        if "THREAT LANDSCAPE" in brief:
            section = brief.split("THREAT LANDSCAPE")[1].split("---")[0].strip()
            summary_text = section.replace("### 2. ", "").strip()
    
    # Compress into context object
    context = {
        "available": True,
        "generated_at": get_utc_now().isoformat(),
        "window_hours": INTEL_WINDOW_HOURS,
        "threat_landscape": {
            "threat_actors": threats.get("threat_actors", []),
            "active_cves": threats.get("active_cves", []),
            "malware_families": threats.get("malware_families", []),
            "summary": summary_text[:500] if summary_text else "No active threat intel available",
        },
        "top_events": [
            {
                "title": e.get("title", ""),
                "source": e.get("source", ""),
                "published": e.get("published", ""),
                "url": e.get("url", ""),
            }
            for e in top_events[:10]  # Limit to 10 for context
        ],
        "stats": {
            "total_cyber_events": len(cyber_events),
            "events_in_window": len(top_events),
            "threat_actors_tracked": len(threats.get("threat_actors", [])),
            "active_cves": len(threats.get("active_cves", [])),
        },
    }
    
    return context


def save_context(context: dict):
    """Save context to cache file."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    with open(OSINT_CACHE, 'w') as f:
        json.dump(context, f, indent=2)


def load_cached_context() -> Optional[dict]:
    """Load cached context if available and fresh (< 6 hours)."""
    if not OSINT_CACHE.exists():
        return None
    
    try:
        with open(OSINT_CACHE) as f:
            context = json.load(f)
        
        # Check if fresh
        generated = parse_timestamp(context.get("generated_at", ""))
        if generated and is_within_window(generated, window_hours=6):
            return context
    except (json.JSONDecodeError, IOError):
        pass
    
    return None


# ── Prompt Builder ─────────────────────────────────────────────────────────────


def build_osint_prompt(context: dict) -> str:
    """
    Build a concise OSINT prompt for the triage model.
    Optimized for token efficiency while preserving key context.
    """
    if not context.get("available"):
        return ""
    
    threat = context.get("threat_landscape", {})
    events = context.get("top_events", [])
    stats = context.get("stats", {})
    
    # Build compact prompt
    lines = [
        "",
        "═══ OSINT THREAT CONTEXT ═══",
        f"Window: Last {context.get('window_hours', 48)}h | Events: {stats.get('events_in_window', 0)} | CVEs: {stats.get('active_cves', 0)}",
        "",
        "ACTIVE THREATS:",
    ]
    
    # Threat actors
    if threat.get("threat_actors"):
        lines.append(f"  • Threat Actors: {', '.join(threat['threat_actors'][:5])}")
    
    # CVEs
    if threat.get("active_cves"):
        lines.append(f"  • Active CVEs: {', '.join(threat['active_cves'][:5])}")
    
    # Malware
    if threat.get("malware_families"):
        lines.append(f"  • Malware: {', '.join(threat['malware_families'][:5])}")
    
    # Summary
    lines.append("")
    lines.append(f"INTEL SUMMARY: {threat.get('summary', 'N/A')[:300]}")
    
    # Top events (compact format)
    if events:
        lines.append("")
        lines.append("TOP EVENTS:")
        for i, e in enumerate(events[:5], 1):
            title = e.get("title", "")[:80]
            source = e.get("source", "")
            lines.append(f"  {i}. [{source}] {title}")
    
    lines.append("")
    lines.append("═══ END OSINT CONTEXT ═══")
    lines.append("")
    
    return "\n".join(lines)


# ── State Tracking ─────────────────────────────────────────────────────────────


def load_osint_state() -> set:
    """Load set of already-processed event hashes."""
    if not OSINT_STATE.exists():
        return set()
    try:
        with open(OSINT_STATE) as f:
            return set(line.strip() for line in f if line.strip())
    except Exception:
        return set()


def save_osint_state(hashes: set):
    """Save processed event hashes."""
    with open(OSINT_STATE, 'w') as f:
        for h in hashes:
            f.write(h + "\n")


def get_new_events(context: dict) -> list[dict]:
    """Get events that haven't been processed before."""
    if not context.get("available"):
        return []
    
    processed = load_osint_state()
    events = context.get("top_events", [])
    
    new_events = []
    for event in events:
        h = event_hash(event)
        if h not in processed:
            new_events.append(event)
            processed.add(h)
    
    # Save state
    save_osint_state(processed)
    
    return new_events


# ── Main ──────────────────────────────────────────────────────────────────────


def refresh_osint_context() -> dict:
    """
    Refresh OSINT context from latest reports.
    Call this before each triage run.
    """
    context = build_osint_context()
    save_context(context)
    return context


def get_osint_prompt_for_triage() -> str:
    """
    Get OSINT prompt for triage model.
    Uses cached context if fresh, otherwise refreshes.
    """
    context = load_cached_context()
    if not context:
        context = refresh_osint_context()
    
    return build_osint_prompt(context)


if __name__ == "__main__":
    # Test run
    print("Refreshing OSINT context...")
    context = refresh_osint_context()
    
    print("\n=== OSINT CONTEXT ===")
    print(json.dumps(context, indent=2))
    
    print("\n=== PROMPT ===")
    print(build_osint_prompt(context))
    
    print("\n=== NEW EVENTS ===")
    new = get_new_events(context)
    for e in new:
        print(f"  • {e.get('title', '')[:60]}")
