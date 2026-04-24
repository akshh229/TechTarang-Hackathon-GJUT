import subprocess
import sys

def run_garak():
    """
    FR-08: Red-Team Benchmark Ready (garak)
    This script provides the baseline runner for garak to evaluate the REST API.
    """
    print("Starting garak baseline tests against AI Firewall...")
    command = [
        "python", "-m", "garak",
        "--model_type", "rest",   # Use rest endpoint
        "--model_name", "http://127.0.0.1:8000/v1/chat/completions",
        "--probes", "promptinject,sqlinject",
    ]
    try:
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Garak tests failed: {e}")
    except FileNotFoundError:
        print("Garak not installed. To run tests: pip install garak")

if __name__ == "__main__":
    run_garak()
