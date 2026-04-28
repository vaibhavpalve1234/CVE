DATA_PATH = "data/processed/cve_dataset.json"
FAISS_INDEX_PATH = "data/embeddings/faiss.index"

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
# SLM_MODEL = "models/slm" 
SLM_MODEL = "distilgpt2"  # or local TinyLlama path


TOP_K = 5
MAX_TOKENS = 200