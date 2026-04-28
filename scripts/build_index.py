import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import DATA_PATH, EMBEDDING_MODEL, FAISS_INDEX_PATH
from src.embedder import Embedder
from src.vector_store import VectorStore


def to_text(record):
    references = " ".join(record.get("references", [])[:3])
    weaknesses = ", ".join(record.get("weaknesses", []))
    return (
        f"{record.get('cve_id', '')} "
        f"severity {record.get('severity', 'UNKNOWN')} "
        f"score {record.get('cvss_score', 'n/a')} "
        f"description {record.get('description', '')} "
        f"weaknesses {weaknesses} "
        f"references {references}"
    ).strip()


def main():
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    texts = [to_text(d) for d in data]

    embedder = Embedder(EMBEDDING_MODEL)
    vecs = embedder.encode(texts)

    vs = VectorStore(len(vecs[0]))
    vs.add(vecs, data)
    vs.save(FAISS_INDEX_PATH)

    print(f"Index built with {len(data)} CVE records")


if __name__ == "__main__":
    main()
