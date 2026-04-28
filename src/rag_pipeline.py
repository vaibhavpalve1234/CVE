import json
from src.embedder import Embedder
from src.vector_store import VectorStore
from src.hybrid_retriever import HybridRetriever
from src.model import LocalModel
from src.json_guard import JSONGuard
from src.reasoning import CVEReasoner
from src.config import EMBEDDING_MODEL, FAISS_INDEX_PATH, TOP_K


class CVERag:
    def __init__(self):
        self.embedder = Embedder(EMBEDDING_MODEL)

        self.vs = VectorStore(384)
        self.vs.load(FAISS_INDEX_PATH)

        self.docs = self.vs.meta
        self.doc_by_id = {doc.get("cve_id", "").upper(): doc for doc in self.docs}
        self.bm25 = HybridRetriever(self.docs)

        self.model = LocalModel()
        self.guard = JSONGuard()
        self.reasoner = CVEReasoner()

    def build_prompt(self, query, docs):
        context = "\n".join(
            [
                f"{d['cve_id']} ({d['severity']}): {d['description']}"
                for d in docs
            ]
        )

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

    def get_cve_details(self, cve_id):
        key = (cve_id or "").strip().upper()
        return self.doc_by_id.get(key)

    def retrieve(self, query, k=TOP_K):
        q_vec = self.embedder.encode([query])

        dense = self.vs.search(q_vec, k)
        sparse = self.bm25.search(query, k)

        seen = set()
        docs = []

        for doc in dense + sparse:
            cve_id = doc.get("cve_id")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                docs.append(doc)

        return docs[:k]

    def ask(self, query, k=TOP_K):
        docs = self.retrieve(query, k)
        prompt = self.build_prompt(query, docs)
        result = self.guard.enforce(self.model, prompt)
        if len(result) > 0:
            d = result[0]
            print(d)
            return {
                "cve_id": d["cve_id"],
                "summary": d["description"],
                "severity": d["severity"],
                "impact": "Potential exploitation risk",
                "mitigation": "Apply latest patch"
            }

        return {"error": "No data"}