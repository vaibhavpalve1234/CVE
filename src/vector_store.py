import faiss, json, numpy as np

class VectorStore:
    def __init__(self, dim):
        self.index = faiss.IndexFlatL2(dim)
        self.meta = []

    def add(self, vecs, meta):
        self.index.add(np.array(vecs).astype("float32"))
        self.meta.extend(meta)

    def save(self, path):
        faiss.write_index(self.index, path)
        json.dump(self.meta, open(path+".meta","w"))

    def load(self, path):
        self.index = faiss.read_index(path)
        self.meta = json.load(open(path+".meta"))

    def search(self, q, k):
        D, I = self.index.search(q, k)
        return [self.meta[i] for i in I[0]]