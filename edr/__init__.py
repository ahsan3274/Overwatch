# EDR package for Overwatch
# Provides hash lookup and YARA scanning for deterministic threat detection

from edr.hash_lookup import MalwareBazaarLookup, HashLookupCache
from edr.yara_scanner import YaraScanner, setup_rule_directories
from edr.edr_ingester import EDREngine, EDRResult, process_queue

__all__ = [
    "MalwareBazaarLookup",
    "HashLookupCache",
    "YaraScanner",
    "setup_rule_directories",
    "EDREngine",
    "EDRResult",
    "process_queue",
]
