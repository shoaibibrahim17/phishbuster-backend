import os
import requests

def check_url_virustotal(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    headers = {
        "x-apikey": api_key
    }

    scan_url = "https://www.virustotal.com/api/v3/urls"
    scan_res = requests.post(scan_url, headers=headers, data={"url": url})

    if scan_res.status_code != 200:
        return {"error": "VirusTotal scan failed"}

    analysis_id = scan_res.json()["data"]["id"]

    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    report_res = requests.get(report_url, headers=headers)

    if report_res.status_code == 200:
        data = report_res.json()
        malicious_count = data["data"]["attributes"]["stats"]["malicious"]
        suspicious_count = data["data"]["attributes"]["stats"]["suspicious"]
        return {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "verdict": "malicious" if malicious_count > 0 else "clean"
        }

    return {"error": "Failed to retrieve VirusTotal report"}
