import requests

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
vulns = requests.get(URL, timeout=30).json()["vulnerabilities"]

def search(question, top_n=3):
    words = [w.lower() for w in question.split() if len(w) > 3]
    scored = []
    for v in vulns:
        text = " ".join([v["vendorProject"], v["product"], v["vulnerabilityName"], v["shortDescription"]]).lower()
        score = sum(text.count(w) for w in words)
        if score > 0:
            scored.append((score, v))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [v for _, v in scored[:top_n]]

queerastion = input("Ask about a vulnbility: ")
for v in search(question):
    print("\n", v["cveID"], "-", v["vulnerabilityName"])
    print(v["shortDescription"])