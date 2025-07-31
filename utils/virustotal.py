import os
import requests
import time
import logging

# Setup basic logging for visibility in production environments
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

VT_API_URL = "https://www.virustotal.com/api/v3/urls"
MAX_POLL_ATTEMPTS = 12  # Poll for up to 60 seconds
POLL_INTERVAL_SECONDS = 5

def _extract_results(analysis_data):
    """Helper function to extract results from a completed analysis object to avoid code duplication."""
    attributes = analysis_data.get("data", {}).get("attributes", {})
    if not attributes:
        logging.warning("Malformed analysis data from VirusTotal, 'attributes' key missing.")
        return {"error": "Malformed analysis data from VirusTotal"}

    stats = attributes.get("stats", {})
    malicious_count = stats.get("malicious", 0)
    suspicious_count = stats.get("suspicious", 0)

    verdict = "clean"
    if malicious_count > 0:
        verdict = "malicious"
    elif suspicious_count > 0:
        verdict = "suspicious"

    return {
        "malicious": malicious_count,
        "suspicious": suspicious_count,
        "verdict": verdict
    }

def check_url_virustotal(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logging.error("VIRUSTOTAL_API_KEY not found in environment variables.")
        return {"error": "Server configuration error: Missing VirusTotal API key."}

    headers = {"x-apikey": api_key}

    # 1. Submit URL for analysis. This returns an analysis object.
    try:
        scan_res = requests.post(VT_API_URL, headers=headers, data={"url": url})
        scan_res.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        analysis_data = scan_res.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"VirusTotal scan submission failed for url '{url}': {e}")
        return {"error": "VirusTotal scan submission failed"}

    # 2. Check if the analysis from the POST is already complete.
    # This avoids a polling loop for URLs that have been recently scanned.
    status = analysis_data.get("data", {}).get("attributes", {}).get("status")
    if status == "completed":
        logging.info(f"VirusTotal analysis for '{url}' was already complete.")
        return _extract_results(analysis_data)

    # 3. If not complete, get the analysis ID and poll the analysis endpoint.
    try:
        analysis_id = analysis_data["data"]["id"]
    except KeyError:
        logging.error(f"Could not get analysis ID from VirusTotal response for '{url}'. Response: {analysis_data}")
        return {"error": "Invalid response from VirusTotal scan submission."}

    report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    logging.info(f"VirusTotal analysis for '{url}' is '{status}'. Polling for completion...")

    for i in range(MAX_POLL_ATTEMPTS):
        time.sleep(POLL_INTERVAL_SECONDS)  # Wait before polling
        try:
            report_res = requests.get(report_url, headers=headers)
            report_res.raise_for_status()
            polled_data = report_res.json()

            status = polled_data.get("data", {}).get("attributes", {}).get("status")
            logging.info(f"Polling attempt {i+1}/{MAX_POLL_ATTEMPTS} for '{url}': Status is '{status}'.")

            if status == "completed":
                return _extract_results(polled_data)

        except requests.exceptions.RequestException as e:
            logging.warning(f"A single VirusTotal poll request failed for '{url}': {e}")
            # Continue to next poll attempt

    logging.error(f"Failed to retrieve completed VirusTotal report for '{url}' in time.")
    return {"error": "Failed to retrieve VirusTotal report in time"}
