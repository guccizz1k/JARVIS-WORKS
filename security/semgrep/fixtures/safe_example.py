"""Benign-only Semgrep fixture. DO NOT IMPORT OR EXECUTE."""
import json
import subprocess
import requests

def safe(payload):
    data = json.loads(payload)
    subprocess.run(["echo", str(data)], check=True)
    return requests.get("https://invalid.example", timeout=5)
