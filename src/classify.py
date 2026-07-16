#!/usr/bin/env python3
"""
classify.py
- Runs a Splunk search for recent honeypot events
- Matches events against rules in lookups/mitre_rules.csv
- Sends classified events to Splunk via HTTP Event Collector (HEC)

Configure environment variables below or edit constants.
"""

import os
import time
import csv
import re
import json
import requests

# === CONFIG ===
SPLUNK_HOST = os.environ.get("SPLUNK_HOST", "localhost")
SPLUNK_REST_PORT = os.environ.get("SPLUNK_REST_PORT", "8089")  # Management port
SPLUNK_HEC_PORT = os.environ.get("SPLUNK_HEC_PORT", "8088")

SPLUNK_USERNAME = os.environ.get("SPLUNK_USERNAME", "")
SPLUNK_PASSWORD = os.environ.get("SPLUNK_PASSWORD", "")
SPLUNK_REST_TOKEN = os.environ.get("SPLUNK_REST_TOKEN", "")

HEC_TOKEN = os.environ.get("HEC_TOKEN", "")      # REQUIRED
HEC_INDEX = os.environ.get("HEC_INDEX", "classified")

RULES_CSV = os.path.join(os.path.dirname(__file__), "..", "lookups", "mitre_rules.csv")

# Splunk search query (modify as needed)
SPLUNK_SEARCH = "search index=honeypot_logs earliest=-5m@m latest=now | head 1000"


# === Load MITRE rules ===
def load_rules(path):
    rules = []
    with open(path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            pattern = row.get("pattern")
            if not pattern:
                continue

            rules.append({
                "re": re.compile(pattern, re.IGNORECASE),
                "meta": row
            })
    return rules


# === Splunk REST Search Job ===
def create_search_job(search_query, session):
    url = f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}/services/search/jobs"

    payload = {
        "search": search_query,
        "earliest_time": "-5m",
        "latest_time": "now",
        "output_mode": "json"
    }

    headers = {}
    if SPLUNK_REST_TOKEN:
        headers["Authorization"] = f"Bearer {SPLUNK_REST_TOKEN}"

    resp = session.post(url, data=payload, headers=headers, verify=False)
    resp.raise_for_status()

    return resp.json()["sid"]


def poll_job_results(sid, session, timeout=60):
    url = (
        f"https://{SPLUNK_HOST}:{SPLUNK_REST_PORT}/services/search/jobs/"
        f"{sid}/results?output_mode=json&count=0"
    )

    headers = {}
    if SPLUNK_REST_TOKEN:
        headers["Authorization"] = f"Bearer {SPLUNK_REST_TOKEN}"

    start = time.time()

    while True:
        resp = session.get(url, headers=headers, verify=False)
        resp.raise_for_status()
        j = resp.json()

        if "results" in j and j["results"]:
            return j["results"]

        if time.time() - start > timeout:
            return []

        time.sleep(1)


# === Classification ===
def classify_event(ev, rules):
    text = (ev.get("command") or ev.get("_raw") or "").lower()

    for r in rules:
        if r["re"].search(text):
            meta = r["meta"]
            return {
                "MITRE_Tactic": meta.get("MITRE_Tactic", "Unknown"),
                "Technique_ID": meta.get("Technique_ID", "Unknown"),
                "Technique_Name": meta.get("Technique_Name", "Unknown"),
                "Likely_APT_Group": meta.get("Likely_APT_Group", "Unknown"),
            }
    return None


# === Send to Splunk HEC ===
def send_to_hec(event, hec_token):
    url = f"http://{SPLUNK_HOST}:{SPLUNK_HEC_PORT}/services/collector/event"

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "time": event.get("_time"),
        "host": event.get("src_ip", "honeypot"),
        "index": HEC_INDEX,
        "sourcetype": "ctassist:classified",
        "event": event
    }

    r = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)
    r.raise_for_status()
    return r.status_code


# === Main Logic ===
def main():
    if not HEC_TOKEN:
        print("ERROR: HEC_TOKEN not set. Please export HEC_TOKEN before running.")
        return

    requests.packages.urllib3.disable_warnings()

    rules = load_rules(RULES_CSV)
    session = requests.Session()

    # Auth priority: REST token > Basic auth
    if SPLUNK_REST_TOKEN:
        session.headers.update({"Authorization": f"Bearer {SPLUNK_REST_TOKEN}"})
    elif SPLUNK_USERNAME and SPLUNK_PASSWORD:
        session.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)

    print("Creating search job...")
    sid = create_search_job(SPLUNK_SEARCH, session)
    print("SID:", sid)

    results = poll_job_results(sid, session, timeout=30)
    if not results:
        print("No results returned.")
        return

    print(f"Fetched {len(results)} events. Classifying...")

    count = 0
    for ev in results:
        classification = classify_event(ev, rules)
        if classification:
            ev.update(classification)
            try:
                send_to_hec(ev, HEC_TOKEN)
                count += 1
            except Exception as e:
                print("Failed to send to HEC:", e)

    print(f"Classification complete. Sent {count} events to HEC index '{HEC_INDEX}'.")


if __name__ == "__main__":
    main()
