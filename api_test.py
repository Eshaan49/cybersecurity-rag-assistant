import requests

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
response = requests.get(url, timeout=30)
data = response.json()

print("Total known exploited vulnerabilities:", len(data["vulnerabilities"]))
for v in data["vulnerabilities"][:3]:
    print(v["cveID"], "-", v["vulnerabilityName"])