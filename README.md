# Cybersecurity RAG Assistant

A small Python tool that answers questions about known exploited vulnerabilities using Retrieval-Augmented Generation (RAG).

## How it works
1. **Retrieval:** downloads the public CISA Known Exploited Vulnerabilities catalog and ranks entries against your question using keyword matching weighted by word rarity (a TF-IDF-style approach).
2. **Generation:** sends the top 3 entries plus your question to the Gemini API, with instructions to answer only from those entries.

## Setup
1. Install dependencies: `pip install requests`
2. Get a free Gemini API key from Google AI Studio and set it as an environment variable (PowerShell): `$env:GEMINI_API_KEY="your-key"`
3. Run: `python rag.py`

If you see an SSL certificate error on Windows, run `pip install pip-system-certs`.

## Example
Question: *What is ProxyNotShell and how does it work?*
Retrieved: CVE-2022-41082 and CVE-2022-41040. The assistant explains they are chained Exchange Server vulnerabilities leading to remote code execution.

## Limitations and next steps
- Keyword search matches words, not meaning. Next step: semantic search with embeddings.
- CISA descriptions are short, so "how it works" answers are thin. Next step: add richer sources such as MITRE ATT&CK.
- Model names in the Gemini API change over time, so update `MODEL` in `rag.py` if you get a 404.

## Built with
Python, requests, CISA KEV data, Gemini API