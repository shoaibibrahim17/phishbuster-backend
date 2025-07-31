# PhishBuster AR - Backend

## Features
- URL Safety Check via Google Safe Browsing
- Threat Detection via VirusTotal API

## Endpoints
- `POST /check` — JSON `{ "url": "<target_url>" }`

## Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Create `.env` file with API keys.
3. Run server: `python app.py`
