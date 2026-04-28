from rank_bm25 import BM25Okapi

class HybridRetriever:
    def __init__(self, docs):
        self.docs = docs
        self.tokenized = [d["description"].split() for d in docs]
        self.bm25 = BM25Okapi(self.tokenized)

    def search(self, query, k=5):
        scores = self.bm25.get_scores(query.split())
        ranked = sorted(zip(self.docs, scores), key=lambda x: x[1], reverse=True)
        return [r[0] for r in ranked[:k]]