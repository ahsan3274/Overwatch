#!/usr/bin/env python3
"""
Overwatch LM Studio CLI Manager
Efficient model loading/unloading via LM Studio CLI
Loads model on-demand for threat scoring, unloads immediately after
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import time
import requests
from datetime import datetime
from pathlib import Path

# Configuration
LM_STUDIO_URL = "http://localhost:1234/v1"
MODEL_NAME = "redsage-qwen3-8b-dpo"
LM_STUDIO_CLI = str(Path.home() / ".lmstudio" / "bin" / "lms")
LOG_FILE = Path.home() / 'velociraptor-triage' / 'lmstudio_manager.log'

# Timeouts
LOAD_TIMEOUT = 120  # Model loading can take time
SCORING_TIMEOUT = 90
MAX_RETRIES = 2

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


class LMStudioCLIManager:
    """Manages LM Studio model lifecycle via CLI for Overwatch"""

    def __init__(self):
        self.model_loaded = False
        self.last_load_time = None

    def _run_lmstudio_cli(self, command: list, timeout: int = 30) -> tuple[bool, str]:
        """
        Run LM Studio CLI command

        Args:
            command: CLI arguments (e.g., ['models', 'load', MODEL_NAME])
            timeout: Command timeout in seconds

        Returns:
            tuple: (success: bool, output: str)
        """
        try:
            # Translate the legacy manager verbs to the current `lms` CLI.
            if command[:2] == ['models', 'load'] and len(command) >= 3:
                cli_args = [
                    'load', command[2],
                    '--identifier', MODEL_NAME,
                    '--yes',
                ]
            elif command[:2] == ['models', 'unload']:
                cli_args = ['unload', MODEL_NAME]
            else:
                cli_args = command

            result = subprocess.run(
                [LM_STUDIO_CLI] + cli_args,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr

        except FileNotFoundError:
            log.debug("lmstudio CLI not found, trying alternative methods")
            return False, "CLI not found"
        except subprocess.TimeoutExpired:
            log.error(f"CLI command timed out after {timeout}s")
            return False, "Timeout"
        except Exception as e:
            log.error(f"CLI error: {e}")
            return False, str(e)

    def check_lmstudio_running(self) -> bool:
        """Check if LM Studio server is running"""
        try:
            response = requests.get(f"{LM_STUDIO_URL}/models", timeout=5)
            return response.status_code == 200
        except Exception as e:
            log.debug(f"LM Studio not responding: {e}")
            return False

    def get_current_model(self) -> str | None:
        """Get currently loaded model name"""
        try:
            response = requests.get(f"{LM_STUDIO_URL}/models", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('data'):
                    return data['data'][0].get('id')
        except Exception as e:
            log.debug(f"Failed to get current model: {e}")
        return None

    def is_correct_model_loaded(self) -> bool:
        """Check if RedSage model is loaded"""
        current = self.get_current_model()
        return current == MODEL_NAME

    def load_model(self) -> bool:
        """
        Load RedSage model via CLI

        Returns:
            bool: True if loaded successfully
        """
        # Check if already loaded
        if self.is_correct_model_loaded():
            log.info("✓ RedSage model already loaded")
            self.model_loaded = True
            self.last_load_time = datetime.now()
            return True

        log.info(f"Loading {MODEL_NAME}...")

        # Loading a model does not guarantee the OpenAI-compatible server is
        # listening. Start it explicitly before loading so verification and
        # scoring can use port 1234 under launchd as well as interactive runs.
        if not self.check_lmstudio_running():
            log.info("Starting LM Studio local server...")
            success, output = self._run_lmstudio_cli(
                ['server', 'start'], timeout=30
            )
            if not success:
                log.error(f"Failed to start LM Studio server: {output[:200]}")
                return False

            for _ in range(30):
                if self.check_lmstudio_running():
                    break
                time.sleep(1)
            else:
                log.error("LM Studio server did not become ready")
                return False

        # Try CLI first
        success, output = self._run_lmstudio_cli(
            ['models', 'load', MODEL_NAME],
            timeout=LOAD_TIMEOUT
        )

        if success:
            log.info(f"✓ {MODEL_NAME} loaded via CLI")
            log.debug(f"CLI output: {output[:200]}")
            self.model_loaded = True
            self.last_load_time = datetime.now()

            # Verify it's actually loaded
            time.sleep(2)
            if self.is_correct_model_loaded():
                return True
            else:
                log.warning("Model load reported success but verification failed")
                return False

        # Fallback: Load via API (dummy request)
        log.info("CLI failed, trying API fallback...")

        for attempt in range(MAX_RETRIES):
            try:
                response = requests.post(
                    f"{LM_STUDIO_URL}/chat/completions",
                    json={
                        "model": MODEL_NAME,
                        "messages": [{"role": "user", "content": "Hi"}],
                        "max_tokens": 1
                    },
                    timeout=LOAD_TIMEOUT
                )

                if response.status_code == 200:
                    log.info(f"✓ {MODEL_NAME} loaded via API (attempt {attempt + 1})")
                    self.model_loaded = True
                    self.last_load_time = datetime.now()
                    return True
                else:
                    log.warning(f"Load attempt {attempt + 1} failed: {response.status_code}")

            except Exception as e:
                log.warning(f"Load attempt {attempt + 1} error: {e}")

            if attempt < MAX_RETRIES - 1:
                time.sleep(2)

        log.error(f"✗ Failed to load {MODEL_NAME} after {MAX_RETRIES} attempts")
        return False

    def unload_model(self, immediate: bool = True) -> bool:
        """
        Unload model via CLI

        Args:
            immediate: If True, use CLI for immediate unload

        Returns:
            bool: True if unloaded successfully
        """
        if not self.model_loaded and not self.is_correct_model_loaded():
            log.debug("Model not loaded, nothing to unload")
            return True

        log.info("Unloading model...")

        # Try CLI unload first
        if immediate:
            success, output = self._run_lmstudio_cli(
                ['models', 'unload'],
                timeout=30
            )

            if success:
                log.info(f"✓ Model unloaded via CLI")
                log.debug(f"CLI output: {output[:200]}")
                self.model_loaded = False
                self.last_load_time = None
                return True
            else:
                log.warning(f"CLI unload failed: {output[:200]}")
                # Continue to API fallback

        # Fallback: API unload (if available)
        try:
            response = requests.post(
                f"{LM_STUDIO_URL}/debug/unload",
                timeout=10
            )

            if response.status_code == 200:
                log.info("✓ Model unloaded via API")
                self.model_loaded = False
                self.last_load_time = None
                return True
        except Exception as e:
            log.debug(f"API unload failed: {e}")

        log.warning("Model unload requested but may still be in memory")
        self.model_loaded = False
        self.last_load_time = None
        return True  # Return True anyway - model will be reloaded on next need

    def shutdown_lmstudio(self) -> bool:
        """Stop the local server and daemon, then quit the LM Studio GUI."""
        success = True

        log.info("Stopping LM Studio local server...")
        server_ok, server_output = self._run_lmstudio_cli(
            ['server', 'stop'], timeout=30
        )
        if not server_ok and 'not running' not in server_output.lower():
            log.warning(f"LM Studio server stop failed: {server_output[:200]}")
            success = False
        elif not server_ok:
            log.debug("LM Studio server was already stopped")

        # Avoid launching LM Studio merely to ask it to quit. AppleScript first
        # checks whether the application is already running.
        try:
            running = subprocess.run(
                ['osascript', '-e', 'application "LM Studio" is running'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if running.returncode == 0 and running.stdout.strip() == 'true':
                quit_result = subprocess.run(
                    ['osascript', '-e', 'tell application "LM Studio" to quit'],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if quit_result.returncode == 0:
                    log.info("✓ LM Studio GUI quit")
                else:
                    log.warning(
                        f"LM Studio GUI quit failed: {quit_result.stderr[:200]}"
                    )
                    success = False
        except Exception as exc:
            log.warning(f"Unable to check or quit LM Studio GUI: {exc}")
            success = False

        log.info("Stopping LM Studio daemon...")
        daemon_ok, daemon_output = self._run_lmstudio_cli(
            ['daemon', 'down'], timeout=30
        )
        if not daemon_ok and 'not running' not in daemon_output.lower():
            log.warning(f"LM Studio daemon stop failed: {daemon_output[:200]}")
            success = False
        elif not daemon_ok:
            log.debug("LM Studio daemon was already stopped")

        if success:
            log.info("✓ LM Studio fully stopped")
        return success

    def ensure_loaded(self) -> bool:
        """
        Ensure model is loaded, load if needed

        Returns:
            bool: True if model is ready for scoring
        """
        if self.is_correct_model_loaded():
            self.last_load_time = datetime.now()
            return True

        return self.load_model()

    def score_threat(self, event_data: dict, unload_after: bool = True) -> dict | None:
        """
        Score a security event using RedSage LLM

        This is the main entry point for Overwatch triage.
        Loads the model on demand and scores one event. Callers processing a
        batch can set ``unload_after=False`` and unload once in their cleanup.

        Args:
            event_data: Event dictionary with process, network, indicators

        Returns:
            dict: Scoring result with risk_score (1-10) and reasoning
            None: If scoring failed
        """
        # Load model on-demand
        log.info("Loading model for threat scoring...")
        if not self.ensure_loaded():
            log.error("Cannot score: model not available")
            return None

        log.info("Model loaded, scoring threat...")

        # Build prompt
        system_prompt = """You are RedSage, a security threat scoring AI.
Analyze the security event and provide a risk score from 1-10.

Response format (JSON only):
{
    "risk_score": 1-10,
    "reasoning": "Brief explanation",
    "threat_type": "malware|backdoor|c2|miner|suspicious|benign",
    "confidence": 0.0-1.0
}

Scoring guide:
- 1-3: Benign system activity
- 4-6: Suspicious but likely false positive
- 7-8: Likely threat, investigate
- 9-10: Confirmed threat, immediate action
"""

        event_json = json.dumps(event_data, indent=2, default=str)
        user_prompt = f"""Security Event Analysis:

{event_json}

Use the complete event above. Missing fields and PID 0 mean metadata was not
provided; they are not threat indicators. A policy-enforcement event is benign
unless it contains independent evidence of compromise. Score this threat:"""

        # Make scoring request
        try:
            response = requests.post(
                f"{LM_STUDIO_URL}/chat/completions",
                json={
                    "model": MODEL_NAME,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "temperature": 0.1,
                    "max_tokens": 256
                },
                timeout=SCORING_TIMEOUT
            )

            if response.status_code != 200:
                log.error(f"Scoring request failed: {response.status_code}")
                if unload_after:
                    self.unload_model()
                return None

            result = response.json()
            content = result['choices'][0]['message']['content'].strip()

            if unload_after:
                log.info("Scoring complete, unloading model...")
                self.unload_model(immediate=True)
            else:
                log.debug("Scoring complete; keeping model loaded for batch")

            # Parse JSON response
            try:
                # Extract JSON from markdown code blocks if present
                if "```" in content:
                    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, re.DOTALL)
                    if json_match:
                        content = json_match.group(1)
                    else:
                        json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)
                        if json_match:
                            content = json_match.group(0)

                score_result = json.loads(content)

                # Validate result
                if not isinstance(score_result, dict):
                    log.error(f"LLM returned non-dict result: {type(score_result)}")
                    return None

                if "risk_score" not in score_result:
                    log.error(f"LLM result missing risk_score: {score_result}")
                    return None

                risk_score = int(score_result.get("risk_score", 0))
                if risk_score < 1 or risk_score > 10:
                    log.error(f"Invalid risk_score {risk_score} (must be 1-10)")
                    return None

                # Extract threat type
                threat_type = score_result.get("threat_type", "unknown")
                if threat_type not in {"malware", "backdoor", "c2", "miner", "suspicious", "benign"}:
                    threat_type = "unknown"

                log.info(f"✓ Threat scored: {risk_score}/10 ({threat_type})")

                return {
                    "risk_score": risk_score,
                    "threat_type": threat_type,
                    "reasoning": score_result.get("reasoning", "No reasoning provided"),
                    "confidence": float(score_result.get("confidence", 0.5)),
                    "raw": score_result
                }

            except json.JSONDecodeError as e:
                log.error(f"Failed to parse LLM response: {e}")
                log.debug(f"Raw response: {content[:500]}")
                return None

        except requests.exceptions.Timeout:
            log.error(f"Scoring timed out after {SCORING_TIMEOUT}s")
            if unload_after:
                self.unload_model()
            return None
        except Exception as e:
            log.error(f"Scoring error: {e}")
            if unload_after:
                self.unload_model()
            return None

    def get_status(self) -> dict:
        """Get current manager status"""
        return {
            'model_loaded': self.model_loaded or self.is_correct_model_loaded(),
            'current_model': self.get_current_model(),
            'last_load_time': self.last_load_time.isoformat() if self.last_load_time else None,
            'lmstudio_running': self.check_lmstudio_running()
        }


# Singleton instance
_manager = None

def get_manager() -> LMStudioCLIManager:
    """Get singleton manager instance"""
    global _manager
    if _manager is None:
        _manager = LMStudioCLIManager()
    return _manager


if __name__ == '__main__':
    # Test/CLI mode
    import sys

    manager = get_manager()

    print("=== Overwatch LM Studio CLI Manager ===")
    print("")

    status = manager.get_status()
    print(f"LM Studio Running: {status['lmstudio_running']}")
    print(f"Model Loaded: {status['model_loaded']}")
    print(f"Current Model: {status['current_model']}")
    print("")

    if len(sys.argv) > 1:
        if sys.argv[1] == 'load':
            print("Loading model...")
            if manager.load_model():
                print("✓ Model loaded")
            else:
                print("✗ Failed to load")

        elif sys.argv[1] == 'unload':
            print("Unloading model...")
            if manager.unload_model():
                print("✓ Model unloaded")
            else:
                print("✗ Failed to unload")

        elif sys.argv[1] == 'status':
            print(f"Status: {status}")

        else:
            print(f"Unknown command: {sys.argv[1]}")
            print("Usage: python lmstudio_manager.py [load|unload|status]")
    else:
        print("Usage: python lmstudio_manager.py [load|unload|status]")
