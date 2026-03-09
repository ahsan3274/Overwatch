#!/usr/bin/env python3
"""
LM Studio Manager - Robust model loading/unloading for the triage daemon.
Handles edge cases like:
- Multiple models loaded
- Model already loaded (different identifier)
- Server not running
- CLI not available
- Timeout handling with retries
"""

from __future__ import annotations

import json
import subprocess
import time
import logging
from typing import Optional

# ── Config ────────────────────────────────────────────────────────────────────

LM_STUDIO_CLI = "lms"
MODEL_NAME = "redsage-qwen3-8b-dpo"
SERVER_URL = "http://localhost:1234"
LOAD_TIMEOUT = 60       # Seconds to wait for model load
UNLOAD_TIMEOUT = 30     # Seconds to wait for model unload
MAX_RETRIES = 3         # Max retries for load/unload operations
CHECK_INTERVAL = 1      # Seconds between status checks

log = logging.getLogger("lmstudio_manager")


# ── Helper Functions ──────────────────────────────────────────────────────────

def run_lms_command(args: list[str], timeout: int = 30) -> tuple[bool, str, str]:
    """
    Run an LM Studio CLI command.
    Returns (success, stdout, stderr).
    """
    try:
        result = subprocess.run(
            [LM_STUDIO_CLI] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return False, "", f"LM Studio CLI '{LM_STUDIO_CLI}' not found"
    except Exception as e:
        return False, "", str(e)


# ── Server Management ─────────────────────────────────────────────────────────

def is_server_running() -> bool:
    """Check if LM Studio server is running."""
    success, stdout, stderr = run_lms_command(["server", "status"], timeout=5)
    if not success:
        return False
    # Status output is on stderr: "The server is running on port 1234."
    output = (stdout + stderr).lower()
    return "running" in output or "port" in output


def start_server() -> bool:
    """Start LM Studio server in background."""
    log.info("Starting LM Studio server...")
    success, stdout, stderr = run_lms_command(["server", "start", "--port", "1234"], timeout=10)
    if not success:
        log.error(f"Failed to start server: {stderr}")
        return False
    
    # Wait for server to be ready
    log.info("Waiting for server to be ready...")
    for _ in range(30):
        time.sleep(1)
        if is_server_running():
            log.info("Server is ready")
            return True
    
    log.error("Server did not become ready in time")
    return False


def stop_server() -> bool:
    """Stop LM Studio server."""
    log.info("Stopping LM Studio server...")
    success, stdout, stderr = run_lms_command(["server", "stop"], timeout=30)
    if not success:
        log.warning(f"Failed to stop server: {stderr}")
        return False
    log.info("Server stopped")
    return True


# ── Model Management ──────────────────────────────────────────────────────────

def get_loaded_models() -> list[dict]:
    """
    Get list of currently loaded models using 'lms ps'.
    Returns list of dicts with 'identifier', 'path', etc.
    """
    success, stdout, _ = run_lms_command(["ps", "--json"], timeout=10)
    if not success:
        return []
    
    try:
        # Parse JSON output
        data = json.loads(stdout)
        if isinstance(data, list):
            return data
        elif isinstance(data, dict) and "models" in data:
            return data["models"]
    except json.JSONDecodeError:
        pass
    
    return []


def unload_all_models() -> bool:
    """Unload all currently loaded models."""
    loaded = get_loaded_models()
    if not loaded:
        log.debug("No models to unload")
        return True
    
    log.info(f"Unloading {len(loaded)} model(s)...")
    
    # Use --all flag to unload everything at once
    success, stdout, stderr = run_lms_command(["unload", "-a"], timeout=UNLOAD_TIMEOUT)
    if not success:
        # Fallback: unload each model individually
        log.warning(f"Batch unload failed: {stderr}, trying individual unloads")
        for model in loaded:
            identifier = model.get("identifier", "") or model.get("id", "")
            if identifier:
                log.info(f"Unloading model: {identifier}")
                run_lms_command(["unload", identifier], timeout=UNLOAD_TIMEOUT)
    
    # Verify all models are unloaded
    time.sleep(2)
    remaining = get_loaded_models()
    if remaining:
        log.warning(f"{len(remaining)} model(s) still loaded after unload")
        return False
    
    log.info("All models unloaded successfully")
    return True


def is_model_loaded(model_name: str = None) -> bool:
    """
    Check if a specific model is loaded.
    If model_name is None, checks if ANY model is loaded.
    """
    loaded = get_loaded_models()
    if not loaded:
        return False
    
    if model_name is None:
        return len(loaded) > 0
    
    # Check if our model is loaded (by identifier or path)
    for model in loaded:
        identifier = model.get("identifier", "") or model.get("id", "")
        path = model.get("path", "")
        
        if model_name in identifier or model_name in path:
            return True
    
    return False


def load_model(model_name: str, wait_for_ready: bool = True, skip_if_loaded: bool = True) -> bool:
    """
    Load a model into LM Studio.

    Note: 'lms load' is a long-running command that stays active while the model
    is loaded. We run it in background and poll for the model to appear.

    Args:
        model_name: The model key/identifier to load
        wait_for_ready: If True, wait for the model to be fully loaded
        skip_if_loaded: If True, return immediately if model is already loaded

    Returns:
        True if successful, False otherwise
    """
    # Check if model is already loaded (skip redundant loads)
    if skip_if_loaded and is_model_loaded(model_name):
        log.info(f"Model '{model_name}' is already loaded, skipping load")
        return True

    log.info(f"Loading model '{model_name}'...")

    # First, unload any existing models to avoid conflicts
    # (Only if we're actually loading a new model)
    loaded_models = get_loaded_models()
    if loaded_models:
        # Check if it's ONLY our model
        if len(loaded_models) == 1:
            identifier = loaded_models[0].get("identifier", "") or loaded_models[0].get("id", "")
            if model_name in identifier:
                log.info(f"Model '{model_name}' is already loaded")
                return True
        # Unload if different model or multiple models loaded
        unload_all_models()

    try:
        # Load with appropriate options for triage use
        # Using --ttl to auto-unload after inactivity
        # Run in background since 'lms load' is long-running
        subprocess.Popen(
            [
                LM_STUDIO_CLI, "load", model_name,
                "--ttl", "300",
                "--context-length", "4096",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        log.info("Model load initiated in background")

        if not wait_for_ready:
            log.info("Not waiting for model to load (wait_for_ready=False)")
            return True

        # Wait for model to be fully loaded
        log.info(f"Waiting for model to load (timeout: {LOAD_TIMEOUT}s)...")
        start = time.time()

        while time.time() - start < LOAD_TIMEOUT:
            if is_model_loaded(model_name):
                log.info(f"Model '{model_name}' loaded successfully")
                return True
            time.sleep(CHECK_INTERVAL)

        log.error(f"Model '{model_name}' did not load within {LOAD_TIMEOUT}s")
        return False

    except Exception as e:
        log.error(f"Failed to load model: {e}")
        return False


def ensure_model_loaded(model_name: str, retry: bool = True) -> bool:
    """
    Ensure a model is loaded, with retry logic.

    This is the main entry point for the triage daemon.
    """
    # Check if already loaded (fast path - no redundant loads)
    if is_model_loaded(model_name):
        log.info(f"Model '{model_name}' is already loaded")
        return True

    # Check if server is running
    if not is_server_running():
        log.info("LM Studio server not running, starting...")
        if not start_server():
            log.error("Failed to start LM Studio server")
            return False

    # Try to load with retries
    attempts = MAX_RETRIES if retry else 1
    for attempt in range(1, attempts + 1):
        log.info(f"Load attempt {attempt}/{attempts}")

        # Pass skip_if_loaded=True to avoid unloading if model got loaded concurrently
        if load_model(model_name, wait_for_ready=True, skip_if_loaded=True):
            return True

        if attempt < attempts:
            log.warning(f"Load attempt {attempt} failed, retrying in 5s...")
            time.sleep(5)

    log.error(f"Failed to load model '{model_name}' after {attempts} attempts")
    return False


def unload_model_when_done(model_name: str = None) -> bool:
    """
    Unload model after processing is complete.
    
    This is the companion to ensure_model_loaded() - call this when done
    processing to free up RAM.
    
    Args:
        model_name: If provided, only unload if this specific model is loaded.
                   If None, unload any loaded model.
    
    Returns:
        True if model was unloaded (or nothing to unload), False on error.
    """
    loaded = get_loaded_models()
    if not loaded:
        log.debug("No models to unload")
        return True
    
    # If model_name specified, check if it's the one loaded
    if model_name:
        for model in loaded:
            identifier = model.get("identifier", "") or model.get("id", "")
            path = model.get("path", "")
            if model_name in identifier or model_name in path:
                log.info(f"Unloading model '{model_name}'...")
                return unload_all_models()
        # Model we wanted isn't loaded
        log.debug(f"Model '{model_name}' not loaded, nothing to unload")
        return True
    
    # Unload whatever is loaded
    log.info(f"Unloading {len(loaded)} model(s)...")
    return unload_all_models()


def get_model_info() -> dict:
    """Get information about the loaded model."""
    loaded = get_loaded_models()
    if not loaded:
        return {"status": "no_model_loaded"}
    
    # Return info about the first loaded model
    model = loaded[0]
    return {
        "status": "loaded",
        "identifier": model.get("identifier", "unknown"),
        "path": model.get("path", "unknown"),
        "context_length": model.get("contextLength", "unknown"),
    }


# ── CLI Interface ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    
    if len(sys.argv) < 2:
        print("Usage: lmstudio_manager.py <command> [args]")
        print("Commands:")
        print("  status     - Show current model status")
        print("  load       - Load the configured model (skips if already loaded)")
        print("  unload     - Unload all models")
        print("  done       - Unload model after processing (alias for unload)")
        print("  restart    - Restart the server and load model")
        print("  check      - Check if model is loaded (exit 0 if yes, 1 if no)")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "status":
        info = get_model_info()
        print(json.dumps(info, indent=2))
    
    elif command == "load":
        if ensure_model_loaded(MODEL_NAME):
            print(f"Model '{MODEL_NAME}' loaded successfully")
            sys.exit(0)
        else:
            print(f"Failed to load model '{MODEL_NAME}'")
            sys.exit(1)
    
    elif command == "unload":
        if unload_all_models():
            print("All models unloaded")
            sys.exit(0)
        else:
            print("Failed to unload models")
            sys.exit(1)

    elif command == "done":
        # Alias for unload - unloads model when processing is done
        if unload_model_when_done(MODEL_NAME):
            print(f"Model '{MODEL_NAME}' unloaded")
            sys.exit(0)
        else:
            print(f"Failed to unload model '{MODEL_NAME}'")
            sys.exit(1)

    elif command == "restart":
        stop_server()
        time.sleep(2)
        start_server()
        if ensure_model_loaded(MODEL_NAME):
            print(f"Server restarted and model '{MODEL_NAME}' loaded")
            sys.exit(0)
        else:
            sys.exit(1)
    
    elif command == "check":
        if is_model_loaded(MODEL_NAME):
            print(f"Model '{MODEL_NAME}' is loaded")
            sys.exit(0)
        else:
            print(f"Model '{MODEL_NAME}' is NOT loaded")
            sys.exit(1)
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
