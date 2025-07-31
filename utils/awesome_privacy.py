import requests
import re

RAW_GITHUB_URL = "https://raw.githubusercontent.com/pluja/awesome-privacy/master/README.md"

def fetch_awesome_privacy():
    print("Fetching awesome-privacy list from GitHub...")
    response = requests.get(RAW_GITHUB_URL)
    if response.status_code != 200:
        print("Failed to fetch data from GitHub.")
        return {}

    content = response.text
    risky_apps = {}

    # Regex pattern to find lines like: "- **Facebook** → [Mastodon](https://joinmastodon.org)"
    matches = re.findall(r"- \*\*(.*?)\*\* → \[(.*?)\]\((.*?)\)", content)
    for original, alt_name, alt_url in matches:
        original_lower = original.lower()
        risky_apps[original_lower] = {
            "alternative_name": alt_name,
            "alternative_url": alt_url
        }

    print(f"Loaded {len(risky_apps)} risky apps from awesome-privacy.")
    return risky_apps

# Optional: test the function locally
if __name__ == "__main__":
    apps = fetch_awesome_privacy()
    for k, v in list(apps.items())[:5]:
        print(f"{k} → {v['alternative_name']} ({v['alternative_url']})")
