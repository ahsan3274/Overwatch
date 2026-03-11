#!/usr/bin/env python3
"""
MalwareBazaar Hash Lookup API Wrapper

Queries MalwareBazaar (https://bazaar.abuse.ch/) for file hash reputation.
No API key required. Rate limit: 100 requests/hour.

Supports:
- SHA256, SHA1, MD5 lookups
- Vendor intelligence aggregation (VirusTotal, ClamAV, Microsoft, etc.)
- Local SQLite caching to reduce API calls
"""

import hashlib
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
log = logging.getLogger(__name__)

# MalwareBazaar API endpoint
MALWARE_BAZAAR_API = "https://bazaar.abuse.ch/api/v1/"

# Cache settings
CACHE_TTL_HOURS = 24
DEFAULT_CACHE_DIR = Path.home() / "velociraptor-triage" / "threat_db"


class HashLookupCache:
    """SQLite cache for hash lookups to reduce API calls."""
    
    def __init__(self, cache_dir: Path = DEFAULT_CACHE_DIR):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "ioc_cache.sqlite"
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hash_lookups (
                sha256 TEXT PRIMARY KEY,
                sha1 TEXT,
                md5 TEXT,
                malware_family TEXT,
                tags TEXT,
                vendors TEXT,
                first_seen TEXT,
                risk_score INTEGER,
                cached_at TEXT,
                expires_at TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache_stats (
                key TEXT PRIMARY KEY,
                value INTEGER
            )
        """)
        conn.commit()
        conn.close()
    
    def get(self, sha256: str) -> Optional[Dict]:
        """Retrieve cached lookup result if not expired."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM hash_lookups WHERE sha256 = ? AND expires_at > ?",
            (sha256, datetime.now().isoformat())
        )
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def set(self, sha256: str, data: Dict, ttl_hours: int = CACHE_TTL_HOURS):
        """Cache a lookup result."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = (datetime.now() + timedelta(hours=ttl_hours)).isoformat()
        
        cursor.execute("""
            INSERT OR REPLACE INTO hash_lookups 
            (sha256, sha1, md5, malware_family, tags, vendors, first_seen, risk_score, cached_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sha256,
            data.get('sha1', ''),
            data.get('md5', ''),
            data.get('malware_family', ''),
            json.dumps(data.get('tags', [])),
            json.dumps(data.get('vendors', {})),
            data.get('first_seen', ''),
            data.get('risk_score', 0),
            datetime.now().isoformat(),
            expires_at
        ))
        
        # Update stats
        cursor.execute(
            "INSERT OR REPLACE INTO cache_stats (key, value) VALUES ('total_entries', COALESCE((SELECT value FROM cache_stats WHERE key='total_entries'), 0) + 1)"
        )
        
        conn.commit()
        conn.close()
    
    def get_stats(self) -> Dict:
        """Get cache statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM hash_lookups")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM hash_lookups WHERE expires_at > ?", (datetime.now().isoformat(),))
        valid = cursor.fetchone()[0]
        
        conn.close()
        return {"total_entries": total, "valid_entries": valid}
    
    def cleanup_expired(self):
        """Remove expired entries from cache."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM hash_lookups WHERE expires_at <= ?", (datetime.now().isoformat(),))
        deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        return deleted


class MalwareBazaarLookup:
    """MalwareBazaar API client for hash reputation lookups."""
    
    def __init__(self, cache: Optional[HashLookupCache] = None, rate_limit_delay: float = 0.5):
        self.cache = cache or HashLookupCache()
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = 0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Overwatch-EDR/1.0",
            "Content-Type": "application/x-www-form-urlencoded"
        })
    
    def _rate_limit(self):
        """Enforce rate limiting to stay within API limits."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate SHA256, SHA1, and MD5 for a file."""
        sha256_hash = hashlib.sha256()
        sha1_hash = hashlib.sha1()
        md5_hash = hashlib.md5()
        
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
                    sha1_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return {
                "sha256": sha256_hash.hexdigest(),
                "sha1": sha1_hash.hexdigest(),
                "md5": md5_hash.hexdigest()
            }
        except (IOError, OSError) as e:
            log.error(f"Failed to hash file {file_path}: {e}")
            return {}
    
    def lookup_sha256(self, sha256: str) -> Optional[Dict]:
        """
        Lookup a SHA256 hash in MalwareBazaar.
        
        Returns:
            Dict with malware info if found, None if unknown/clean.
        """
        # Check cache first
        cached = self.cache.get(sha256)
        if cached:
            log.debug(f"Cache hit for {sha256[:16]}...")
            return cached if cached.get('malware_family') else None
        
        # API lookup
        self._rate_limit()
        
        try:
            response = self.session.post(
                MALWARE_BAZAAR_API,
                data={"query": "get_info", "sha256_hash": sha256},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()
            
            if data.get("query_status") == "ok" and data.get("data"):
                result = self._parse_result(data["data"], sha256)
                self.cache.set(sha256, result)
                return result if result.get('malware_family') else None
            else:
                # Unknown hash - cache as clean
                self.cache.set(sha256, {"sha256": sha256, "risk_score": 0})
                return None
                
        except requests.exceptions.RequestException as e:
            log.error(f"MalwareBazaar API error for {sha256[:16]}...: {e}")
            return None
        except json.JSONDecodeError as e:
            log.error(f"Failed to parse API response: {e}")
            return None
    
    def _parse_result(self, data: Dict, sha256: str) -> Dict:
        """Parse MalwareBazaar API response into standardized format."""
        # Handle both single object and array responses
        if isinstance(data, list):
            data = data[0] if data else {}
        
        # Extract vendor detections
        vendors = {}
        vendor_intel = data.get("vendor_intel", {})
        
        for vendor_name, detections in vendor_intel.items():
            if isinstance(detections, list) and detections:
                # VirusTotal format: [{detection: "MalwareName", score: X}]
                if isinstance(detections[0], dict):
                    vendors[vendor_name] = detections[0].get("detection", "detected")
                else:
                    vendors[vendor_name] = detections[0] if detections else "unknown"
        
        # Determine primary malware family
        malware_family = data.get("malware_family", "")
        if not malware_family and vendors:
            # Use most common vendor detection
            malware_family = list(vendors.values())[0]
        
        # Calculate risk score (0-10)
        vendor_count = len(vendors)
        risk_score = min(10, vendor_count * 2)  # 2 points per vendor detection
        
        return {
            "sha256": sha256,
            "sha1": data.get("sha1", ""),
            "md5": data.get("md5", ""),
            "malware_family": malware_family,
            "tags": data.get("tags", []),
            "vendors": vendors,
            "first_seen": data.get("first_seen", ""),
            "risk_score": risk_score,
            "vendor_count": vendor_count
        }
    
    def lookup_file(self, file_path: str) -> Optional[Dict]:
        """
        Lookup a file by calculating its hash and querying MalwareBazaar.
        
        Returns:
            Dict with malware info if found, None if unknown/clean.
        """
        hashes = self.calculate_hashes(file_path)
        if not hashes:
            return None
        
        log.debug(f"Looking up {file_path} (SHA256: {hashes['sha256'][:16]}...)")
        return self.lookup_sha256(hashes["sha256"])
    
    def bulk_lookup(self, file_paths: List[str]) -> Dict[str, Optional[Dict]]:
        """
        Lookup multiple files.
        
        Returns:
            Dict mapping file_path -> malware info (or None if clean).
        """
        results = {}
        for i, path in enumerate(file_paths):
            log.debug(f"[{i+1}/{len(file_paths)}] Looking up {path}")
            results[path] = self.lookup_file(path)
        return results


def test_lookup():
    """Test function to verify MalwareBazaar integration."""
    lookup = MalwareBazaarLookup()
    
    # Test with known malware hash (EICAR test file)
    # EICAR is a safe test file recognized by all AV vendors
    eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    eicar_sha256 = hashlib.sha256(eicar_content).hexdigest()
    
    print(f"Testing with EICAR hash: {eicar_sha256}")
    result = lookup.lookup_sha256(eicar_sha256)
    
    if result:
        print(f"✅ Detected: {result.get('malware_family', 'Unknown')}")
        print(f"   Risk Score: {result.get('risk_score')}/10")
        print(f"   Vendors: {list(result.get('vendors', {}).keys())}")
    else:
        print("⚠️  Not detected (may be unknown or rate limited)")
    
    # Show cache stats
    stats = lookup.cache.get_stats()
    print(f"\nCache Stats: {stats}")


if __name__ == "__main__":
    test_lookup()
