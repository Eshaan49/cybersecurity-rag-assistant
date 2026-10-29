# 🛡️ Cybersecurity RAG Assistant

![Status](https://img.shields.io/badge/Status-WORKING-brightgreen?style=for-the-badge) ![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white) ![Gemini](https://img.shields.io/badge/Gemini_API-LLM-4285F4?style=for-the-badge) ![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

A command-line assistant that answers questions about vulnerabilities attackers are exploiting **right now** — using only CISA's official catalog as its source, and showing exactly which CVEs each answer came from.

---

### ⚡ Overview

General-purpose chatbots answer security questions from memory, which means they can be outdated or confidently wrong. **Cybersecurity RAG Assistant** takes a different approach: it downloads CISA's live *Known Exploited Vulnerabilities* (KEV) catalog, retrieves the entries most relevant to your question, and instructs the language model to answer **only from those entries**. If the retrieved entries don't contain the answer, it says so.

Every answer is printed with its **source CVE IDs**, so the output can be checked against the original record.

---

### 📊 At a Glance

| Metric | Value |
|---|---|
| Data source | CISA Known Exploited Vulnerabilities catalog (live JSON feed) |
| Entries indexed | 1,700+ CVEs (1,760 at time of testing) |
| Retrieval method | Keyword search weighted by word rarity (TF-IDF-style) |
| Generation | Gemini API, restricted to retrieved entries |
| Answer traceability | Source CVE IDs printed with every answer |
| Secret handling | API key read from an environment variable, never stored in code |

---

### ✨ Key Features

- 📡 **Live data** — pulls the current CISA KEV feed on each run, so answers reflect the latest catalog
- 🎯 **Rarity-weighted retrieval** — distinctive terms (like a vulnerability nickname) count far more than filler words
- 🧾 **Grounded answers** — the model is instructed to use *only* the retrieved entries and to admit when they don't answer the question
- 🔎 **Source transparency** — the CVE IDs behind each answer are shown before the answer itself
- 🔐 **Safe credential handling** — the API key lives in an environment variable and `.gitignore` blocks `.env` files

---

### 🧪 Example

```
Ask about a vulnerability: What is ProxyNotShell and how does it work?

Sources: CVE-2022-41082, CVE-2022-41040

Answer:
 "ProxyNotShell" refers to a chained set of Microsoft Exchange Server
 vulnerabilities:
 * CVE-2022-41040: server-side request forgery
 * CVE-2022-41082: authenticated remote code execution
 The two are chained together to allow remote code execution.
```

---

### ⚙️ Architecture

```
 Question
    │
    ▼
┌──────────────────┐     ┌────────────────────────────┐
│ CISA KEV feed    │────▶│ Retrieval                  │
│ (1,700+ CVEs)    │     │ rarity-weighted keyword    │
└──────────────────┘     │ ranking → top 3 entries    │
                         └─────────────┬──────────────┘
                                       │
                                       ▼
                         ┌────────────────────────────┐
                         │ Grounded prompt            │
                         │ "Answer ONLY from these    │
                         │  entries"                  │
                         └─────────────┬──────────────┘
                                       │
                                       ▼
                         ┌────────────────────────────┐
                         │ Gemini API → answer        │
                         │ + source CVE IDs           │
                         └────────────────────────────┘
```

---

### 🔩 Pipeline Phases

| Phase | Component | What it does |
|---|---|---|
| 1 | Data ingestion | Downloads the CISA KEV JSON feed over HTTPS |
| 2 | Retrieval | `search()` — filters filler words, weights each remaining word by how rare it is across the catalog, ranks entries by score |
| 3 | Prompt grounding | Builds a prompt containing only the top entries and an instruction to answer from them alone |
| 4 | Generation | `ask_ai()` — calls the Gemini REST API and returns the answer with its source CVEs |

---

### 🛠️ Engineering Notes

**A retrieval bug worth documenting.** The first version of the search counted every word equally. Asked *"What is ProxyNotShell and how does it work?"*, it returned three unrelated CVEs, because common words like "what", "does" and "work" outscored the one distinctive term. The fix was to drop filler words and weight each remaining word by `1 / (number of entries containing it)`, so rare terms dominate. The same question now returns the two correct CVEs. This is the core idea behind TF-IDF.

**Secure by default.** The Gemini API key is read from the `GEMINI_API_KEY` environment variable. Nothing secret is committed to this repository, and `.env` files are git-ignored.

**TLS verification stays on.** On some Windows networks, Python rejects certificates that the operating system trusts. The fix used here is `pip install pip-system-certs`, which makes Python use the Windows certificate store, rather than disabling certificate verification.

---

### 📦 Installation

```bash
git clone https://github.com/Eshaan49/cybersecurity-rag-assistant.git
cd cybersecurity-rag-assistant
pip install -r requirements.txt
```

Get a free API key from [Google AI Studio](https://aistudio.google.com) and set it as an environment variable. Never hardcode it.

```powershell
# Windows PowerShell
$env:GEMINI_API_KEY="your_key_here"
```

```bash
# macOS / Linux
export GEMINI_API_KEY="your_key_here"
```

Run it:

```bash
python rag.py
```

> If you hit an SSL certificate error on Windows, run `pip install pip-system-certs`.
> If you get a 404 model error, model names change over time. Run `python check.py` to list the models available to your key, then update `MODEL` in `rag.py`.

---

### 📁 Project Structure

```
cybersecurity-rag-assistant/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── rag.py          # Main assistant: retrieval + grounded generation
├── search.py       # Early retrieval-only prototype (simple keyword counting)
├── api_test.py     # First test of the CISA KEV feed
└── check.py        # Lists the Gemini models available to your API key
```

---

### 🧰 Technologies

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) ![requests](https://img.shields.io/badge/requests-REST_client-blue?style=flat-square) ![CISA](https://img.shields.io/badge/CISA-KEV_Catalog-critical?style=flat-square) ![Gemini](https://img.shields.io/badge/Gemini-API-4285F4?style=flat-square)

---

### 🗺️ Roadmap

- **Semantic search with embeddings** — match on meaning, not just shared words, so retrieval handles paraphrased questions
- **Richer knowledge sources** — add MITRE ATT&CK technique descriptions so "how it works" answers have more depth than CISA's short summaries
- **Local caching** of the CISA feed to avoid re-downloading on every run
- **Configurable model** — read the model name from an environment variable instead of editing code
- **Simple web interface** on top of the command-line tool

---

### 👤 Author

**Eshaan Pilar**
Final-year Cybersecurity Engineering student · Building toward a SOC Analyst role
[GitHub](https://github.com/Eshaan49) · [LinkedIn](https://linkedin.com/in/eshaanpilar)

---

### 📄 License

MIT License — see [LICENSE](LICENSE) for details.