#!/usr/bin/env python3
"""
EDR Ingester for Overwatch

Main EDR engine that combines:
- MalwareBazaar hash reputation lookup
- YARA rule scanning
- Local IOC caching
- Risk score calculation

Integrates with triage_daemon.py to provide pre-scoring before LLM analysis.
"""

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from edr.hash_lookup import MalwareBazaarLookup, HashLookupCache
from edr.yara_scanner import YaraScanner, setup_rule_directories

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

# Default paths
DEFAULT_STATE_DIR = Path.home() / "velociraptor-triage"
DEFAULT_EDR_STATE_FILE = DEFAULT_STATE_DIR / "edr_state.json"
DEFAULT_EDR_LOG_FILE = DEFAULT_STATE_DIR / "edr_ingester.log"


@dataclass
class EDRResult:
    """Combined EDR analysis result for a single file/event."""
    file_path: str
    sha256: Optional[str]
    
    # Hash lookup results
    hash_match: bool
    malware_family: Optional[str]
    hash_vendors: Dict
    hash_risk_score: int
    
    # YARA results
    yara_match: bool
    yara_rules_matched: List[str]
    yara_risk_score: int
    yara_threat_category: str
    
    # Combined assessment
    edr_detected: bool
    combined_risk_score: int  # 0-10
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    detection_source: str  # hash, yara, both
    confidence: str  # low, medium, high
    
    # Metadata
    scan_time_ms: float
    timestamp: str
    
    def to_dict(self) -> Dict:
        return asdict(self)


class EDREngine:
    """
    Main EDR engine combining hash lookup and YARA scanning.
    
    Usage:
        engine = EDREngine()
        result = engine.scan_file("/path/to/suspicious/file")
        if result.edr_detected:
            print(f"THREAT: {result.malware_family} (Risk: {result.combined_risk_score}/10)")
    """
    
    def __init__(
        self,
        enable_hash_lookup: bool = True,
        enable_yara: bool = True,
        yara_rule_dirs: Optional[List[Path]] = None
    ):
        self.enable_hash_lookup = enable_hash_lookup
        self.enable_yara = enable_yara
        
        # Initialize hash lookup
        if self.enable_hash_lookup:
            try:
                self.hash_lookup = MalwareBazaarLookup()
                log.info("Hash lookup enabled (MalwareBazaar)")
            except Exception as e:
                log.warning(f"Failed to initialize hash lookup: {e}")
                self.hash_lookup = None
                self.enable_hash_lookup = False
        else:
            self.hash_lookup = None
        
        # Initialize YARA scanner
        if self.enable_yara:
            try:
                setup_rule_directories()  # Ensure directories exist
                self.yara_scanner = YaraScanner(rule_dirs=yara_rule_dirs)
                stats = self.yara_scanner.get_stats()
                if stats['rules_loaded'] > 0:
                    log.info(f"YARA scanning enabled ({stats['rules_loaded']} rule files)")
                else:
                    log.warning("YARA enabled but no rules found")
            except ImportError as e:
                log.warning(f"YARA not available: {e}")
                self.yara_scanner = None
                self.enable_yara = False
            except Exception as e:
                log.warning(f"Failed to initialize YARA scanner: {e}")
                self.yara_scanner = None
                self.enable_yara = False
        else:
            self.yara_scanner = None
        
        # Stats tracking
        self.stats = {
            "files_scanned": 0,
            "threats_detected": 0,
            "hash_lookups": 0,
            "yara_scans": 0,
            "cache_hits": 0,
            "api_calls": 0,
        }
    
    def scan_file(self, file_path: str) -> Optional[EDRResult]:
        """
        Scan a file with all enabled EDR methods.
        
        Returns:
            EDRResult if file exists and is scannable, None otherwise.
        """
        start_time = time.time()
        
        # Verify file exists
        if not os.path.isfile(file_path):
            log.debug(f"File not found: {file_path}")
            return None
        
        self.stats["files_scanned"] += 1
        
        # Initialize result
        result = EDRResult(
            file_path=file_path,
            sha256=None,
            hash_match=False,
            malware_family=None,
            hash_vendors={},
            hash_risk_score=0,
            yara_match=False,
            yara_rules_matched=[],
            yara_risk_score=0,
            yara_threat_category="clean",
            edr_detected=False,
            combined_risk_score=0,
            risk_level="LOW",
            detection_source="none",
            confidence="low",
            scan_time_ms=0,
            timestamp=datetime.now().isoformat()
        )
        
        # Hash lookup
        if self.enable_hash_lookup and self.hash_lookup:
            self.stats["hash_lookups"] += 1
            hash_result = self.hash_lookup.lookup_file(file_path)
            
            if hash_result:
                result.sha256 = hash_result.get('sha256')
                result.hash_match = True
                result.malware_family = hash_result.get('malware_family')
                result.hash_vendors = hash_result.get('vendors', {})
                result.hash_risk_score = hash_result.get('risk_score', 0)
                
                if hash_result.get('vendor_count', 0) > 5:
                    self.stats["api_calls"] += 1
                else:
                    self.stats["cache_hits"] += 1
        
        # YARA scan
        if self.enable_yara and self.yara_scanner:
            self.stats["yara_scans"] += 1
            yara_result = self.yara_scanner.scan_file(file_path)
            
            if yara_result.match_count > 0:
                result.yara_match = True
                result.yara_rules_matched = [m.rule_name for m in yara_result.matches]
                result.yara_risk_score = yara_result.risk_score
                result.yara_threat_category = yara_result.threat_category
        
        # Calculate combined risk
        self._calculate_combined_risk(result)
        
        # Update stats
        result.scan_time_ms = (time.time() - start_time) * 1000
        if result.edr_detected:
            self.stats["threats_detected"] += 1
        
        return result
    
    def _calculate_combined_risk(self, result: EDRResult):
        """Calculate combined risk score from all detection methods."""
        scores = []
        sources = []
        
        # Hash reputation (high confidence)
        if result.hash_match:
            scores.append(result.hash_risk_score)
            sources.append("hash")
        
        # YARA match (medium-high confidence)
        if result.yara_match:
            scores.append(result.yara_risk_score)
            sources.append("yara")
        
        # No detections
        if not scores:
            result.combined_risk_score = 0
            result.risk_level = "LOW"
            result.detection_source = "none"
            result.confidence = "low"
            result.edr_detected = False
            return
        
        # Combine scores (take max, with bonus for multiple detections)
        max_score = max(scores)
        bonus = 2 if len(scores) > 1 else 0  # Bonus for corroborating detections
        result.combined_risk_score = min(10, max_score + bonus)
        
        # Determine detection source
        if len(sources) > 1:
            result.detection_source = "both"
        else:
            result.detection_source = sources[0]
        
        # Determine risk level
        if result.combined_risk_score >= 9:
            result.risk_level = "CRITICAL"
        elif result.combined_risk_score >= 7:
            result.risk_level = "HIGH"
        elif result.combined_risk_score >= 4:
            result.risk_level = "MEDIUM"
        else:
            result.risk_level = "LOW"
        
        # Determine confidence
        if result.detection_source == "both":
            result.confidence = "high"
        elif result.hash_match and result.hash_risk_score >= 8:
            result.confidence = "high"
        elif result.yara_match and result.yara_risk_score >= 7:
            result.confidence = "medium"
        else:
            result.confidence = "low"
        
        # Final detection flag
        result.edr_detected = result.combined_risk_score >= 4
    
    def scan_files(self, file_paths: List[str]) -> List[EDRResult]:
        """Scan multiple files."""
        return [result for path in file_paths if (result := self.scan_file(path))]
    
    def scan_event(self, event: Dict) -> Optional[EDRResult]:
        """
        Scan an event from the Overwatch event queue.
        
        Expects event format from triage_daemon.py:
        {
            "source": "filemonitor",
            "path": "/path/to/file",
            "event_type": "file_event",
            ...
        }
        """
        # Extract file path from event
        file_path = event.get("path") or event.get("file_path")
        
        if not file_path:
            return None
        
        # Skip non-file events
        if not os.path.isfile(file_path):
            return None
        
        return self.scan_file(file_path)
    
    def get_stats(self) -> Dict:
        """Get EDR engine statistics."""
        stats = self.stats.copy()
        
        if self.hash_lookup:
            stats["hash_lookup_enabled"] = True
            cache_stats = self.hash_lookup.cache.get_stats()
            stats["cache_entries"] = cache_stats["valid_entries"]
        else:
            stats["hash_lookup_enabled"] = False
        
        if self.yara_scanner:
            yara_stats = self.yara_scanner.get_stats()
            stats["yara_enabled"] = True
            stats["yara_rules"] = yara_stats["rules_loaded"]
        else:
            stats["yara_enabled"] = False
            stats["yara_rules"] = 0
        
        return stats
    
    def save_state(self, state_file: Path = DEFAULT_EDR_STATE_FILE):
        """Save EDR state to file."""
        state = {
            "stats": self.get_stats(),
            "last_updated": datetime.now().isoformat()
        }
        
        state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        log.debug(f"EDR state saved to {state_file}")
    
    def load_state(self, state_file: Path = DEFAULT_EDR_STATE_FILE) -> Dict:
        """Load EDR state from file."""
        if not state_file.exists():
            return {}
        
        try:
            with open(state_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            log.warning(f"Failed to load EDR state: {e}")
            return {}


def process_queue(
    queue_file: Path = DEFAULT_STATE_DIR / "event_queue.jsonl",
    output_file: Path = DEFAULT_STATE_DIR / "edr_results.jsonl",
    max_events: int = 100
):
    """
    Process events from the Overwatch queue through EDR scanning.
    
    This is the main entry point for integration with triage_daemon.py.
    """
    log.info(f"Processing EDR queue: {queue_file}")
    
    if not queue_file.exists():
        log.warning(f"Queue file not found: {queue_file}")
        return []
    
    # Initialize EDR engine
    engine = EDREngine()
    
    # Read events from queue
    events = []
    with open(queue_file, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    
    if not events:
        log.info("No events in queue")
        return []
    
    log.info(f"Processing {len(events)} event(s) through EDR...")
    
    # Process events
    results = []
    for i, event in enumerate(events[:max_events]):
        log.debug(f"[{i+1}/{len(events)}] Scanning event from {event.get('source', 'unknown')}")
        
        result = engine.scan_event(event)
        if result and result.edr_detected:
            results.append(result.to_dict())
            log.info(f"  ⚠️  THREAT: {result.malware_family or result.yara_threat_category} "
                    f"(Risk: {result.combined_risk_score}/10, Confidence: {result.confidence})")
    
    # Write results
    if results:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'a') as f:
            for result in results:
                f.write(json.dumps(result) + '\n')
        log.info(f"Wrote {len(results)} threat(s) to {output_file}")
    
    # Save state
    engine.save_state()
    
    # Print stats
    stats = engine.get_stats()
    log.info(f"EDR Stats: {stats['files_scanned']} files, "
            f"{stats['threats_detected']} threats, "
            f"{stats['hash_lookups']} hash lookups, "
            f"{stats['yara_scans']} YARA scans")
    
    return results


def main():
    """Main entry point for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Overwatch EDR Ingester")
    parser.add_argument("--queue", type=str, default=str(DEFAULT_STATE_DIR / "event_queue.jsonl"),
                       help="Path to event queue file")
    parser.add_argument("--output", type=str, default=str(DEFAULT_STATE_DIR / "edr_results.jsonl"),
                       help="Path to output results file")
    parser.add_argument("--max-events", type=int, default=100,
                       help="Maximum events to process")
    parser.add_argument("--no-hash", action="store_true",
                       help="Disable hash lookup")
    parser.add_argument("--no-yara", action="store_true",
                       help="Disable YARA scanning")
    parser.add_argument("--test", action="store_true",
                       help="Run test scan")
    
    args = parser.parse_args()
    
    if args.test:
        # Test mode
        print("Overwatch EDR Test Mode")
        print("=" * 50)
        engine = EDREngine(enable_hash_lookup=not args.no_hash, enable_yara=not args.no_yara)
        stats = engine.get_stats()
        print(f"Hash Lookup: {'✅' if stats['hash_lookup_enabled'] else '❌'}")
        print(f"YARA Scanning: {'✅' if stats['yara_enabled'] else '❌'} ({stats['yara_rules']} rules)")
        print(f"Cache Entries: {stats.get('cache_entries', 0)}")
        return
    
    # Normal processing
    process_queue(
        queue_file=Path(args.queue),
        output_file=Path(args.output),
        max_events=args.max_events
    )


if __name__ == "__main__":
    main()
