from sentence_transformers import SentenceTransformer

class Embedder:
    def __init__(self, name):
        self.model = SentenceTransformer(name)

    def encode(self, texts):
        return self.model.encode(texts, show_progress_bar=True)