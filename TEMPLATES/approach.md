# approach.md (Template)
Explain your pipeline (rules → LLM), constraints, and how to reproduce end‑to‑end.

PIPELINE: 
    Input (inventory_raw.csv)
        ↓
    [1] Deterministic Validation
        - IP address validation (IPv4/IPv6)
        - MAC address normalization
        - Hostname/FQDN validation
        - Owner field parsing
        - Site name normalization
        ↓
    [2] Ambiguity Detection
        - Flag records needing AI judgment
        - Batch ambiguous cases
        ↓
    [3] AI Classification
        - Device type inference
        - Confidence scoring
        - Reasoning capture
        ↓
    [4] Output Generation
        - inventory_clean.csv (normalized records)
        - anomalies.json (validation issues)

REQUIREMENTS:
    pip install groq
    export GROQ_API_KEY="your-api-key"

EXECUTION:
    python run.py (May provide custom .csv file if default one is not available)

CONSTRAINTS:
    [1] Deterministic Validation is not comprehensive and limited to author's knowledge of networking fundamentals.
    [2] LLM Initialization requires valid API Key for operation, otherwise falls back to some basic rule set defined by the author to not completely make DataRgent useless without such key available.
    [3] LLM Classification is limited to device types.