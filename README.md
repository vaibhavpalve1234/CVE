# Offline CVE RAG AI

## Setup

python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

## Run

python scripts/build_index.py
python src/cli.py

## Train Model

python train/finetune_lora.py

## Evaluate

python eval/full_eval.py