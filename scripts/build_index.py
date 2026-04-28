import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import json
from src.embedder import Embedder
from src.vector_store import VectorStore
from src.config import *

data = json.load(open(DATA_PATH))

texts = [d["description"] for d in data]

embedder = Embedder(EMBEDDING_MODEL)
vecs = embedder.encode(texts)

vs = VectorStore(len(vecs[0]))
vs.add(vecs, data)
vs.save(FAISS_INDEX_PATH)

print("Index built")