#!/usr/bin/env python3
"""
YARA Rule Scanner for Overwatch EDR

Scans files against YARA rules to detect malware, packers, and suspicious patterns.
Supports multiple rule sources:
- LOKI signatures (Neo23x0/Loki)
- VirusTotal YARA rules
- Custom user rules

Requires: yara-python (pip install yara-python)
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

# Default rule directories
DEFAULT_RULE_DIRS = [
    Path.home() / "velociraptor-triage" / "edr" / "yara_rules",
    Path(__file__).parent / "yara_rules",
]

# Rule source URLs (for documentation/setup)
RULE_SOURCES = {
    "loki": "https://github.com/Neo23x0/Loki/tree/master/signature",
    "vt-yara": "https://github.com/VirusTotal/yara-rules",
    "yara-rules": "https://github.com/Yara-Rules/rules",
}


@dataclass
class YaraMatch:
    """Represents a YARA rule match."""
    rule_name: str
    namespace: str
    file_path: str
    strings: List[Tuple[str, str, int]]  # (string_name, string_value, offset)
    tags: List[str]
    meta: Dict
    
    def to_dict(self) -> Dict:
        return {
            "rule_name": self.rule_name,
            "namespace": self.namespace,
            "file_path": self.file_path,
            "strings": [(s[0], s[1][:50] if len(s[1]) > 50 else s[1], s[2]) for s in self.strings],
            "tags": self.tags,
            "meta": self.meta,
        }


@dataclass
class ScanResult:
    """Result of a YARA scan."""
    file_path: str
    matches: List[YaraMatch]
    match_count: int
    risk_score: int  # 0-10
    threat_category: str
    scan_time_ms: float
    
    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "matches": [m.to_dict() for m in self.matches],
            "match_count": self.match_count,
            "risk_score": self.risk_score,
            "threat_category": self.threat_category,
            "scan_time_ms": self.scan_time_ms,
        }


class YaraScanner:
    """YARA rule scanner with support for multiple rule sources."""
    
    def __init__(
        self,
        rule_dirs: Optional[List[Path]] = None,
        max_file_size_mb: int = 50,
        timeout_seconds: int = 30
    ):
        if not YARA_AVAILABLE:
            raise ImportError(
                "yara-python not installed. Install with: pip install yara-python"
            )
        
        self.rule_dirs = rule_dirs or DEFAULT_RULE_DIRS
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.timeout_seconds = timeout_seconds
        self.compiled_rules: Optional[yara.Rules] = None
        self.rule_count = 0
        self._load_rules()
    
    def _load_rules(self):
        """Load and compile YARA rules from all configured directories."""
        rule_files = []
        
        for rule_dir in self.rule_dirs:
            if not rule_dir.exists():
                log.debug(f"Rule directory not found: {rule_dir}")
                continue
            
            for root, _, files in os.walk(rule_dir):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        rule_files.append(Path(root) / file)
        
        if not rule_files:
            log.warning("No YARA rules found. Scanner will always return clean.")
            self.compiled_rules = None
            self.rule_count = 0
            return
        
        log.info(f"Loading {len(rule_files)} YARA rule file(s)...")
        
        try:
            # Compile all rules
            self.compiled_rules = yara.compile(
                filepaths={str(f): str(f) for f in rule_files},
                includes=True
            )
            
            # Count rules (approximate - YARA doesn't expose exact count)
            self.rule_count = len(rule_files)
            log.info(f"Loaded {self.rule_count} YARA rule file(s) successfully")
            
        except yara.Error as e:
            log.error(f"Failed to compile YARA rules: {e}")
            self.compiled_rules = None
            self.rule_count = 0
    
    def _check_file_size(self, file_path: str) -> bool:
        """Check if file is within size limits."""
        try:
            size = os.path.getsize(file_path)
            if size > self.max_file_size:
                log.debug(f"Skipping {file_path}: size {size} exceeds limit")
                return False
            return True
        except OSError:
            return False
    
    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a single file against all YARA rules.
        
        Returns:
            ScanResult with matches and risk assessment.
        """
        import time
        start_time = time.time()
        
        # Check file size
        if not self._check_file_size(file_path):
            return ScanResult(
                file_path=file_path,
                matches=[],
                match_count=0,
                risk_score=0,
                threat_category="skipped_size",
                scan_time_ms=(time.time() - start_time) * 1000
            )
        
        # Scan
        matches = []
        try:
            if self.compiled_rules:
                yara_matches = self.compiled_rules.match(
                    file_path,
                    timeout=self.timeout_seconds
                )
                
                for match in yara_matches:
                    yara_match = YaraMatch(
                        rule_name=match.rule,
                        namespace=match.namespace,
                        file_path=file_path,
                        strings=[(s.identifier, s.data, s.offset) for s in match.strings],
                        tags=match.tags,
                        meta=match.meta
                    )
                    matches.append(yara_match)
        
        except yara.TimeoutError:
            log.warning(f"YARA scan timeout for {file_path}")
            return ScanResult(
                file_path=file_path,
                matches=[],
                match_count=0,
                risk_score=0,
                threat_category="timeout",
                scan_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            log.error(f"YARA scan error for {file_path}: {e}")
            return ScanResult(
                file_path=file_path,
                matches=[],
                match_count=0,
                risk_score=0,
                threat_category="error",
                scan_time_ms=(time.time() - start_time) * 1000
            )
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(matches)
        threat_category = self._determine_threat_category(matches)
        
        return ScanResult(
            file_path=file_path,
            matches=matches,
            match_count=len(matches),
            risk_score=risk_score,
            threat_category=threat_category,
            scan_time_ms=(time.time() - start_time) * 1000
        )
    
    def scan_files(self, file_paths: List[str]) -> List[ScanResult]:
        """Scan multiple files."""
        return [self.scan_file(path) for path in file_paths]
    
    def _calculate_risk_score(self, matches: List[YaraMatch]) -> int:
        """
        Calculate risk score (0-10) based on YARA matches.
        
        Scoring:
        - Malware family match: +8
        - Suspicious/behavioral match: +5
        - Packer/crypter match: +4
        - Generic suspicious strings: +2
        """
        score = 0
        
        for match in matches:
            rule_name = match.rule_name.lower()
            tags = [t.lower() for t in match.tags]
            
            # High confidence malware
            if any(kw in rule_name for kw in ['malware', 'trojan', 'rat', 'backdoor', 'stealer']):
                score += 8
            elif any(kw in tags for kw in ['malware', 'trojan', 'rat']):
                score += 8
            
            # Suspicious behavior
            elif any(kw in rule_name for kw in ['suspicious', 'payload', 'shellcode']):
                score += 5
            elif any(kw in tags for kw in ['suspicious', 'payload']):
                score += 5
            
            # Packers/crypters (often legitimate but suspicious)
            elif any(kw in rule_name for kw in ['packer', 'crypter', 'obfuscated']):
                score += 4
            elif any(kw in tags for kw in ['packer', 'crypter']):
                score += 4
            
            # Generic indicators
            else:
                score += 2
        
        return min(10, score)
    
    def _determine_threat_category(self, matches: List[YaraMatch]) -> str:
        """Determine primary threat category from matches."""
        if not matches:
            return "clean"
        
        categories = set()
        for match in matches:
            rule_name = match.rule_name.lower()
            tags = [t.lower() for t in match.tags]
            
            if any(kw in rule_name for kw in ['malware', 'trojan', 'rat', 'backdoor']):
                categories.add('malware')
            elif any(kw in rule_name for kw in ['packer', 'crypter']):
                categories.add('packer')
            elif any(kw in rule_name for kw in ['suspicious']):
                categories.add('suspicious')
            elif any(kw in tags for kw in ['malware', 'trojan']):
                categories.add('malware')
        
        if 'malware' in categories:
            return 'malware'
        elif 'packer' in categories:
            return 'packer'
        elif 'suspicious' in categories:
            return 'suspicious'
        else:
            return 'yara_match'
    
    def reload_rules(self):
        """Reload YARA rules (useful after updating rule files)."""
        log.info("Reloading YARA rules...")
        self._load_rules()
    
    def get_stats(self) -> Dict:
        """Get scanner statistics."""
        return {
            "yara_available": YARA_AVAILABLE,
            "rules_loaded": self.rule_count,
            "rule_directories": [str(d) for d in self.rule_dirs],
        }


def setup_rule_directories():
    """Create default YARA rule directories with setup instructions."""
    for rule_dir in DEFAULT_RULE_DIRS:
        rule_dir.mkdir(parents=True, exist_ok=True)
        
        # Create README with setup instructions
        readme_path = rule_dir / "README.md"
        if not readme_path.exists():
            readme_path.write_text("""# YARA Rules Directory

Place your YARA rules in this directory. Overwatch will automatically load all `.yar` and `.yara` files.

## Recommended Rule Sources

### 1. LOKI Signatures
```bash
git clone https://github.com/Neo23x0/Loki.git
cp -r Loki/signature/* ~/velociraptor-triage/edr/yara_rules/
```

### 2. VirusTotal YARA Rules
```bash
git clone https://github.com/VirusTotal/yara-rules.git
cp yara-rules/*.yar ~/velociraptor-triage/edr/yara_rules/
```

### 3. Yara-Rules Project
```bash
git clone https://github.com/Yara-Rules/rules.git
cp rules/*.yar ~/velociraptor-triage/edr/yara_rules/
```

## Rule File Format

Rules should be in standard YARA format:
```yara
rule Example_Malware {
    meta:
        description = "Example malware detection"
        author = "Your Name"
        date = "2026-01-01"
    
    strings:
        $a = "malicious_string"
    
    condition:
        $a
}
```
""")
            log.info(f"Created YARA rules directory: {rule_dir}")


def test_scanner():
    """Test function to verify YARA scanner."""
    if not YARA_AVAILABLE:
        print("❌ yara-python not installed")
        print("   Install with: pip install yara-python")
        return
    
    # Setup directories
    setup_rule_directories()
    
    # Create scanner
    scanner = YaraScanner()
    stats = scanner.get_stats()
    
    print(f"YARA Scanner Status:")
    print(f"  Available: {stats['yara_available']}")
    print(f"  Rules Loaded: {stats['rules_loaded']} files")
    print(f"  Rule Directories: {stats['rule_directories']}")
    
    if stats['rules_loaded'] == 0:
        print("\n⚠️  No YARA rules found. Install rules from:")
        for name, url in RULE_SOURCES.items():
            print(f"   - {name}: {url}")


if __name__ == "__main__":
    test_scanner()
