import yaml
import threading
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Global thread-safe variable to hold the active policy configuration
_active_policy = {}
_policy_lock = threading.Lock()

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
    if new_config:
        with _policy_lock:
            _active_policy = new_config
        print(f"Policy updated successfully from {filepath}")

def get_policy_config() -> dict:
    """Returns a copy of the current active policy."""
    with _policy_lock:
        return _active_policy.copy()

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
