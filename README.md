# Offline CVE RAG AI

## Setup

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Get CVE data from NVD API v2.0

### Full download (all CVEs)

```bash
python scripts/fetch_nvd_v2.py --output data/raw/nvd_cves_v2.json
```

### Incremental sync (last modified window)

```bash
python scripts/fetch_nvd_v2.py \
  --output data/raw/nvd_updates_jan_2026.json \
  --last-mod-start 2026-01-01T00:00:00.000 \
  --last-mod-end 2026-01-31T23:59:59.000
```

Optional: set `NVD_API_KEY` in your environment for better rate limits.

## Process downloaded NVD v2.0 JSON

```bash
python src/preprocess.py
```

This creates `data/processed/cve_dataset.json` including:
- `cve_id`
- `description`
- `severity`
- `cvss_score`
- `cvss_vector`
- `published`
- `last_modified`
- `references`
- `weaknesses`

## Build the local vector index

```bash
python scripts/build_index.py
```

## Query and detail lookup

### Exact CVE details from local index metadata

```bash
python src/cli.py --cve-id CVE-2021-44228
```

### Query with broader retrieval

```bash
python src/cli.py --query "Show critical remote code execution CVEs" --top-k 10
```

### Interactive mode

```bash
python src/cli.py --top-k 10
```

Type `exit` or `quit` to stop.

## Train model

```bash
python train/finetune_lora.py
```

## Evaluate

```bash
python eval/full_eval.py
```
