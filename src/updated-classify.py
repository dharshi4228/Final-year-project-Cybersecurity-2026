import json
import re
import os
import sys
from datetime import datetime
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------
# Splunk HEC Configuration
# -----------------------------
SPLUNK_HEC_URL = "https://127.0.0.1:8088/services/collector"
SPLUNK_TOKEN = "PUT_YOUR_SPLUNK_HEC_TOKEN_HERE"
SPLUNK_INDEX = "main"
SPLUNK_SOURCETYPE = "apt:honeypot"

# -----------------------------
# MITRE ATT&CK Mapping
# -----------------------------
MITRE_MAPPING = {
    "ssh_bruteforce": {
        "tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110"
    },
    "valid_login": {
        "tactic": "Initial Access",
        "technique": "Valid Accounts",
        "technique_id": "T1078"
    },
    "command_execution": {
        "tactic": "Execution",
        "technique": "Command and Scripting Interpreter",
        "technique_id": "T1059"
    },
    "file_download": {
        "tactic": "Command and Control",
        "technique": "Ingress Tool Transfer",
        "technique_id": "T1105"
    },
    "system_discovery": {
        "tactic": "Discovery",
        "technique": "System Information Discovery",
        "technique_id": "T1082"
    },
    "persistence_attempt": {
        "tactic": "Persistence",
        "technique": "Modify Authentication Process",
        "technique_id": "T1556"
    }
}

# -----------------------------
# Utility Functions
# -----------------------------
def iso_time():
    return datetime.utcnow().isoformat() + "Z"


def output_event(src_ip, source, behavior, raw):
    mitre = MITRE_MAPPING.get(behavior)
    if not mitre:
        return None

    return {
        "timestamp": iso_time(),
        "source": source,
        "src_ip": src_ip,
        "behavior": behavior,
        "mitre_tactic": mitre["tactic"],
        "mitre_technique": mitre["technique"],
        "mitre_technique_id": mitre["technique_id"],
        "raw_event": raw
    }


def send_to_splunk(event):
    payload = {
        "event": event,
        "sourcetype": SPLUNK_SOURCETYPE,
        "index": SPLUNK_INDEX
    }

    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}"
    }

    try:
        requests.post(
            SPLUNK_HEC_URL,
            json=payload,
            headers=headers,
            verify=False,
            timeout=3
        )
    except Exception as e:
        print(f"[!] Splunk send failed: {e}")

# -----------------------------
# JSON Log Processing (Cowrie)
# -----------------------------
def process_json(file_path):
    results = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            try:
                event = json.loads(line)
            except:
                continue

            src_ip = event.get("src_ip", "unknown")
            eventid = event.get("eventid", "")
            message = json.dumps(event)

            if eventid == "cowrie.login.failed":
                results.append(output_event(src_ip, "cowrie", "ssh_bruteforce", message))

            elif eventid == "cowrie.login.success":
                results.append(output_event(src_ip, "cowrie", "valid_login", message))

            elif eventid == "cowrie.command.input":
                cmd = event.get("input", "")
                results.append(output_event(src_ip, "cowrie", "command_execution", cmd))

                if re.search(r"(uname|whoami|ifconfig|ip addr|lsb_release)", cmd):
                    results.append(output_event(src_ip, "cowrie", "system_discovery", cmd))

            elif eventid == "cowrie.session.file_download":
                results.append(output_event(src_ip, "cowrie", "file_download", message))

    return results

# -----------------------------
# LOG File Processing (Conpot / Others)
# -----------------------------
def process_log(file_path):
    results = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            src_ip = "unknown"
            ip_match = re.search(r"\d+\.\d+\.\d+\.\d+", line)
            if ip_match:
                src_ip = ip_match.group()

            lower = line.lower()

            if "login failed" in lower or "authentication failure" in lower:
                results.append(output_event(src_ip, "log", "ssh_bruteforce", line))

            elif "login succeeded" in lower:
                results.append(output_event(src_ip, "log", "valid_login", line))

            elif any(x in lower for x in ["wget", "curl", "tftp"]):
                results.append(output_event(src_ip, "log", "file_download", line))

            elif any(x in lower for x in ["uname", "whoami", "ifconfig", "ip addr"]):
                results.append(output_event(src_ip, "log", "system_discovery", line))

            elif "chmod" in lower or "authorized_keys" in lower:
                results.append(output_event(src_ip, "log", "persistence_attempt", line))

            elif "command" in lower:
                results.append(output_event(src_ip, "log", "command_execution", line))

    return results

# -----------------------------
# Classification Controller
# -----------------------------
def classify(path):
    all_events = []

    if os.path.isfile(path):
        files = [path]
    else:
        files = [os.path.join(path, f) for f in os.listdir(path)]

    for file in files:
        if file.endswith(".json"):
            all_events.extend(process_json(file))
        elif file.endswith(".log"):
            all_events.extend(process_log(file))

    return [e for e in all_events if e]

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 classify.py <log_file_or_directory>")
        sys.exit(1)

    events = classify(sys.argv[1])

    for event in events:
        print(json.dumps(event))
        send_to_splunk(event)
