import os
import requests

url = "https://generativelanguage.googleapis.com/v1beta/models"
resp = requests.get(url, headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"]}, timeout=30)
print("Status:", resp.status_code)
if resp.status_code == 200:
    for m in resp.json().get("models", []):
        if "flash" in m["name"]:
            print(m["name"])
else:
    print(resp.text[:300])