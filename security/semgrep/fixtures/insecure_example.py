"""Positive-only Semgrep fixture. DO NOT IMPORT OR EXECUTE."""
import pickle
import subprocess
import requests

def dangerous(payload):
    eval(payload)
    subprocess.run(["echo", payload], shell=True)
    pickle.loads(payload)
    return requests.get("https://invalid.example", verify=False)
