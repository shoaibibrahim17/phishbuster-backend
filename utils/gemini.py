import os
import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

def suggest_alternatives(risky_app_name):
    prompt = (
        f"List three safe, open-source, and privacy-focused alternatives to the Android app "
        f"'{risky_app_name}'. For each alternative, provide a one-sentence description and confirm "
        f"it's available on the Google Play Store. Present the output in a clean, simple bullet list format."
    )

    try:
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Could not fetch Gemini suggestions: {str(e)}"
