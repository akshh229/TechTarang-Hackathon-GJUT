import os
import threading
from copy import deepcopy
from pathlib import Path

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global thread-safe variable to hold the active policy configuration
_active_policy = {}
_policy_lock = threading.Lock()

REQUIRED_CONFIG_SECTIONS = {
    "llm",
    "sql_policy",
    "injection_rules",
    "pii_patterns",
    "risk_thresholds",
}


def _deep_merge(base: dict, overlay: dict) -> dict:
    merged = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def get_policy_overlay_path(filepath: str) -> str:
    configured_overlay = os.getenv("POLICY_OVERLAY_PATH")
    if configured_overlay:
        return configured_overlay

    base_path = Path(filepath)
    return str(base_path.with_name("policy.auto.yaml"))


def validate_config(config: dict) -> tuple[bool, str]:
    """Basic structural validation so bad hot-reloads do not replace a healthy policy."""
    if not isinstance(config, dict):
        return False, "Policy root must be a mapping."

    missing_sections = REQUIRED_CONFIG_SECTIONS.difference(config.keys())
    if missing_sections:
        missing = ", ".join(sorted(missing_sections))
        return False, f"Missing required config sections: {missing}"

    if not isinstance(config.get("llm"), dict):
        return False, "Config section 'llm' must be a mapping."
    if not isinstance(config.get("sql_policy"), dict):
        return False, "Config section 'sql_policy' must be a mapping."
    if not isinstance(config.get("injection_rules"), list):
        return False, "Config section 'injection_rules' must be a list."
    if not isinstance(config.get("pii_patterns"), dict):
        return False, "Config section 'pii_patterns' must be a mapping."
    if not isinstance(config.get("risk_thresholds"), dict):
        return False, "Config section 'risk_thresholds' must be a mapping."

    risk_thresholds = config["risk_thresholds"]
    amber = risk_thresholds.get("amber")
    red = risk_thresholds.get("red")
    if not isinstance(amber, int) or not isinstance(red, int):
        return False, "Risk thresholds 'amber' and 'red' must be integers."
    if amber < 0 or red < 0 or amber >= red:
        return False, "Risk thresholds must satisfy 0 <= amber < red."

    rate_limit = config.get("rate_limit", {})
    if rate_limit and not isinstance(rate_limit, dict):
        return False, "Config section 'rate_limit' must be a mapping."

    security = config.get("security", {})
    if security and not isinstance(security, dict):
        return False, "Config section 'security' must be a mapping."
    if security and "max_body_bytes" in security:
        max_body_bytes = security["max_body_bytes"]
        if not isinstance(max_body_bytes, int) or max_body_bytes <= 0:
            return False, "Config section 'security.max_body_bytes' must be a positive integer."

    adaptive_defense = config.get("adaptive_defense", {})
    if adaptive_defense and not isinstance(adaptive_defense, dict):
        return False, "Config section 'adaptive_defense' must be a mapping."
    if adaptive_defense:
        prompt_guardrails = adaptive_defense.get("prompt_guardrails", [])
        if prompt_guardrails and not (
            isinstance(prompt_guardrails, list)
            and all(isinstance(item, str) and item.strip() for item in prompt_guardrails)
        ):
            return False, "Config section 'adaptive_defense.prompt_guardrails' must be a list of strings."

        active_families = adaptive_defense.get("active_families", [])
        if active_families and not (
            isinstance(active_families, list)
            and all(isinstance(item, str) and item.strip() for item in active_families)
        ):
            return False, "Config section 'adaptive_defense.active_families' must be a list of strings."

        protected_surfaces = adaptive_defense.get("protected_surfaces", [])
        if protected_surfaces and not (
            isinstance(protected_surfaces, list)
            and all(isinstance(item, str) and item.strip() for item in protected_surfaces)
        ):
            return False, "Config section 'adaptive_defense.protected_surfaces' must be a list of strings."

        semantic_signals = adaptive_defense.get("semantic_signals", [])
        if semantic_signals and not isinstance(semantic_signals, list):
            return False, "Config section 'adaptive_defense.semantic_signals' must be a list."

        for signal in semantic_signals:
            if not isinstance(signal, dict):
                return False, "Each adaptive defense semantic signal must be a mapping."
            pattern = signal.get("pattern")
            weight = signal.get("weight")
            if not isinstance(pattern, str) or not pattern.strip():
                return False, "Each adaptive defense semantic signal needs a non-empty 'pattern'."
            if not isinstance(weight, int) or weight <= 0:
                return False, "Each adaptive defense semantic signal needs a positive integer 'weight'."

    return True, ""

def load_yaml_config(filepath: str) -> dict:
    """Loads a YAML configuration file securely."""
    if not os.path.exists(filepath):
        print(f"Warning: Policy file {filepath} not found.")
        return {}
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            return config if config else {}
    except Exception as e:
        print(f"Error loading YAML config: {e}")
        return {}

def load_combined_config(filepath: str, overlay_path: str | None = None) -> dict:
    base_config = load_yaml_config(filepath)
    resolved_overlay_path = overlay_path or get_policy_overlay_path(filepath)
    overlay_config = load_yaml_config(resolved_overlay_path)

    if not base_config:
        return {}
    if not overlay_config:
        return base_config
    return _deep_merge(base_config, overlay_config)

def update_active_policy(filepath: str, overlay_path: str | None = None):
    """Updates the global active policy with a lock to ensure thread safety."""
    global _active_policy
    new_config = load_combined_config(filepath, overlay_path)
    if not new_config:
        return

    is_valid, message = validate_config(new_config)
    if not is_valid:
        print(f"Rejected invalid policy from {filepath}: {message}")
        return

    with _policy_lock:
        _active_policy = new_config
    print(f"Policy updated successfully from {filepath}")

def get_policy_config() -> dict:
    """Returns a copy of the current active policy."""
    with _policy_lock:
        return deepcopy(_active_policy)

class PolicyFileHandler(FileSystemEventHandler):
    """Watchdog handler that reloads the policy file upon modification."""
    def __init__(self, filepaths: list[str]):
        resolved_paths = [os.path.abspath(filepath) for filepath in filepaths]
        self.filepaths = set(resolved_paths)
        self.primary_filepath = resolved_paths[0]
        super().__init__()

    def on_modified(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) in self.filepaths:
            print(f"Detected modification in {event.src_path}. Reloading policy...")
            update_active_policy(self.primary_filepath)

def init_config_watcher(filepath: str) -> Observer:
    """Initializes and starts the Watchdog observer on the policy file's directory."""
    abs_filepath = os.path.abspath(filepath)
    overlay_path = os.path.abspath(get_policy_overlay_path(abs_filepath))
    update_active_policy(abs_filepath, overlay_path) # Initial load
    
    watched_directories = {os.path.dirname(abs_filepath), os.path.dirname(overlay_path)}
    for directory in watched_directories:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
        # Create empty policy file if it doesn't exist to allow watching
        if not os.path.exists(abs_filepath):
            with open(abs_filepath, 'w') as f:
                f.write("# Auto-generated policy file\n")
    
    event_handler = PolicyFileHandler([abs_filepath, overlay_path])
    observer = Observer()
    for directory in watched_directories:
        observer.schedule(event_handler, path=directory, recursive=False)
    observer.start()
    
    return observer
