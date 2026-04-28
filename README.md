# Offline CVE RAG AI

## Setup

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Build the local index

```bash
python scripts/build_index.py
```

## Get CVE details

### 1) Fetch all stored details for one exact CVE ID

Use this when you want the complete record currently stored in your local index metadata.

```bash
python src/cli.py --cve-id CVE-2021-44228
```

### 2) Ask a question and retrieve multiple matching CVEs

Increase `--top-k` to include more CVEs in retrieval context.

```bash
python src/cli.py --query "Show critical remote code execution CVEs" --top-k 10
```

### 3) Interactive mode

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
