import json
from src.embedder import Embedder
from src.vector_store import VectorStore
from src.hybrid_retriever import HybridRetriever
from src.model import LocalModel
from src.json_guard import JSONGuard
from src.reasoning import CVEReasoner
from src.config import *

class CVERag:
    def __init__(self):
        self.embedder = Embedder(EMBEDDING_MODEL)

        self.vs = VectorStore(384)
        self.vs.load(FAISS_INDEX_PATH)

        self.docs = self.vs.meta
        self.bm25 = HybridRetriever(self.docs)

        self.model = LocalModel()
        self.guard = JSONGuard()
        self.reasoner = CVEReasoner()

    def build_prompt(self, query, docs):
        context = "\n".join([
            f"{d['cve_id']} ({d['severity']}): {d['description']}"
            for d in docs
        ])

        return f"""
STRICT RULES:
- Only use context
- Output valid JSON

Context:
{context}

Query:
{query}

Return:
{{
 "cve_id":"",
 "summary":"",
 "severity":"",
 "impact":"",
 "mitigation":""
}}
"""

    def ask(self, query):
        q_vec = self.embedder.encode([query])

        dense = self.vs.search(q_vec, 3)
        sparse = self.bm25.search(query, 3)

        docs = dense + sparse

        prompt = self.build_prompt(query, docs)

        result = self.guard.enforce(self.model, prompt)

        return result