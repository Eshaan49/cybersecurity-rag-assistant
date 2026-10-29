import os
import requests

API_KEY = os.environ["GEMINI_API_KEY"]
MODEL = "gemini-3.5-flash-lite"  # if you get a 404 error, see my note below
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

vulns = requests.get(CISA_URL, timeout=30).json()["vulnerabilities"]

STOP = {"what", "does", "how", "with", "that", "this", "from", "work", "works",
        "about", "which", "when", "where", "into", "have", "been", "explain"}

def search(question, top_n=3):
    words = [w.strip("?.,!").lower() for w in question.split()]
    words = [w for w in words if len(w) > 3 and w not in STOP]
    texts = [(" ".join([v["vendorProject"], v["product"], v["vulnerabilityName"], v["shortDescription"]]).lower(), v) for v in vulns]
    # rarer words get a bigger weight
    weights = {}
    for w in words:
        df = sum(1 for t, _ in texts if w in t)
        weights[w] = 1 / df if df else 0
    scored = []
    for t, v in texts:
        score = sum(weights[w] * t.count(w) for w in words)
        if score > 0:
            scored.append((score, v))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [v for _, v in scored[:top_n]]

def ask_ai(question, results):
    context = "\n\n".join(f'{v["cveID"]}: {v["vulnerabilityName"]}. {v["shortDescription"]}' for v in results)
    prompt = (
        "You are a cybersecurity assistant. Answer the question using ONLY the "
        "CISA entries below. If they don't contain the answer, say so.\n\n"
        f"ENTRIES:\n{context}\n\nQUESTION: {question}"
    )
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
    resp = requests.post(
        url,
        headers={"x-goog-api-key": API_KEY, "Content-Type": "application/json"},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=120,
    )
    if resp.status_code != 200:
        return f"API error {resp.status_code}: {resp.text}"
    return resp.json()["candidates"][0]["content"]["parts"][0]["text"]

question = input("Ask about a vulnerability: ")
results = search(question)
print("\nSources:", ", ".join(v["cveID"] for v in results))
print("\nAnswer:\n", ask_ai(question, results))