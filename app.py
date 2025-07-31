from flask import Flask, request, jsonify
import os
import logging
from utils.safebrowsing import check_url_safebrowsing
from utils.virustotal import check_url_virustotal
from utils.awesome_privacy import fetch_awesome_privacy
from utils.gemini import suggest_alternatives

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# Load risky apps dynamically from awesome-privacy GitHub repo
RISKY_APPS_DYNAMIC = fetch_awesome_privacy()

@app.route('/')
def home():
    return jsonify({"message": "PhishBuster AR Backend Running"})


@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get("url")
        
        if not url:
            return jsonify({"error": "URL is required"}), 400

        logging.info(f"Checking URL: {url}")

        result_sb = check_url_safebrowsing(url)
        result_vt = check_url_virustotal(url)
        gemini_suggestions = suggest_alternatives(url)

        combined_result = {
            "safe_browsing": result_sb,
            "virus_total": result_vt,
            "safe_alternative_suggestions": gemini_suggestions
        }

        return jsonify(combined_result)

    except Exception as e:
        logging.error(f"Error in /check endpoint: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/analyze', methods=['POST'])
def analyze_app():
    try:
        data = request.get_json()
        app_name = data.get("app_name", "").lower()
        package_name = data.get("package_name", "").lower()

        if not app_name or not package_name:
            return jsonify({"error": "app_name and package_name are required"}), 400

        logging.info(f"Analyzing app: {app_name} ({package_name})")

        for risky in RISKY_APPS_DYNAMIC:
            if risky in app_name or risky in package_name:
                alt = RISKY_APPS_DYNAMIC[risky]
                gemini_suggestions = suggest_alternatives(app_name)
                return jsonify({
                    "app_name": app_name,
                    "package_name": package_name,
                    "risky": True,
                    "reason": f"'{risky}' is considered potentially unsafe or outdated.",
                    "recommended_alternative": alt["alternative_name"],
                    "alternative_url": alt["alternative_url"],
                    "gemini_suggestions": gemini_suggestions
                })

        return jsonify({
            "app_name": app_name,
            "package_name": package_name,
            "risky": False,
            "reason": "This app is considered safe."
        })

    except Exception as e:
        logging.error(f"Error in /analyze endpoint: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
