import os
import threading
from copy import deepcopy

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

def update_active_policy(filepath: str):
    """Updates the global active policy with a lock to ensure thread safety."""
    global _active_policy
    new_config = load_yaml_config(filepath)
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
    def __init__(self, filepath: str):
        self.filepath = os.path.abspath(filepath)
        super().__init__()

    def on_modified(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) == self.filepath:
            print(f"Detected modification in {self.filepath}. Reloading policy...")
            update_active_policy(self.filepath)

def init_config_watcher(filepath: str) -> Observer:
    """Initializes and starts the Watchdog observer on the policy file's directory."""
    abs_filepath = os.path.abspath(filepath)
    update_active_policy(abs_filepath) # Initial load
    
    directory = os.path.dirname(abs_filepath)
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        # Create empty policy file if it doesn't exist to allow watching
        if not os.path.exists(abs_filepath):
            with open(abs_filepath, 'w') as f:
                f.write("# Auto-generated policy file\n")
    
    event_handler = PolicyFileHandler(abs_filepath)
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=False)
    observer.start()
    
    return observer
