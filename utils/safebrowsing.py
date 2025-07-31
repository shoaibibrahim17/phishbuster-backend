import os
import requests
import os

def check_url_safebrowsing(url):
    api_key = os.getenv("SAFE_BROWSING_API_KEY")
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client": {"clientId": "phishbuster", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        }
    }

    response = requests.post(endpoint, json=payload)
    if response.ok:
        data = response.json()
        return {"threat": bool(data.get("matches"))}
    return {"error": "Safe Browsing API failed"}
