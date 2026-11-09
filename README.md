# Cybersecurity RAG Assistant

A command-line assistant that retrieves relevant records from CISA's Known Exploited Vulnerabilities (KEV) catalog and asks Gemini to answer from those records. The project remains a lightweight Python application with no database or external service beyond CISA and Gemini.

## How it works

1. Validate the Gemini API key and read the configured model.
2. Fetch and validate the CISA KEV JSON feed.
3. Search the catalog using exact CVE ID matching followed by the existing rarity-weighted keyword ranking.
4. If no evidence matches, report that no answer was generated. Otherwise, send the retrieved entries to Gemini and display the returned answer with the retrieved CVE IDs.

Retrieval is lexical and uses CISA KEV records only. It does not yet use embeddings, BM25, or additional cybersecurity sources. The model is instructed to use the retrieved entries, but generated claims are not independently verified.

## Project structure

```text
cybersecurity_rag/
  config.py       Environment-based settings and validation
  cisa.py         CISA feed retrieval and schema checks
  retrieval.py    Exact CVE and rarity-weighted keyword retrieval
  gemini.py       Gemini API client and response validation
  app.py          Application orchestration and CLI flow
rag.py            Main assistant entry point
search.py         Retrieval-only compatibility CLI
api_test.py       CISA feed diagnostic
check.py          Gemini model-list diagnostic
tests/            Mocked pytest tests
```

## Requirements and installation

Python 3.10 or newer is recommended. Install runtime dependencies from the repository root:

```bash
python -m pip install -r requirements.txt
```

To run the test suite, also install the development requirements:

```bash
python -m pip install -r requirements-dev.txt
```

## Configuration

Set `GEMINI_API_KEY` in the process environment. The key is never stored in the repository. The default model is `gemini-3.5-flash-lite`; override it with `GEMINI_MODEL` if needed.

PowerShell:

```powershell
$env:GEMINI_API_KEY = "your_key_here"
# Optional:
$env:GEMINI_MODEL = "gemini-3.5-flash-lite"
```

macOS/Linux:

```bash
export GEMINI_API_KEY="your_key_here"
# Optional:
export GEMINI_MODEL="gemini-3.5-flash-lite"
```

The application reads these variables from the process environment; it does not load a `.env` file.

## Run

From the repository root:

```bash
python rag.py
```

Retrieval-only mode:

```bash
python search.py
```

Diagnostics:

```bash
python api_test.py  # Fetch and summarize the KEV feed
python check.py     # List Gemini Flash models available to the key
```

The diagnostics make network requests only when run as scripts. Importing these modules does not prompt or contact external services.

## Tests

Tests use mocked HTTP boundaries and do not require API credentials or external network access:

```bash
python -m pytest
```

## Security and limitations

- API keys are read from the environment and sent in the Gemini request header.
- Network calls use finite timeouts, and provider error details are not included in user-facing exceptions.
- Invalid feed entries are skipped; an invalid feed envelope or a nonempty feed with no usable entries is rejected.
- The catalog is fetched at application start and held in memory for that run; there is no cache or offline fallback.
- Retrieval is lexical. Exact CVE IDs are prioritized, but paraphrased questions may not find relevant records.
- The model is prompted to answer from retrieved evidence. The application reports retrieved CVE IDs but does not yet validate each generated claim or citation.

## License

MIT. See [LICENSE](LICENSE).
