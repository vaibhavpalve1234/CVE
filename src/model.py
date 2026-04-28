from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from src.config import *

class LocalModel:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained(SLM_MODEL)
        self.model = AutoModelForCausalLM.from_pretrained(SLM_MODEL)

        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.to(self.device)

    def generate(self, prompt):
        inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)

        out = self.model.generate(
            **inputs,
            max_new_tokens=MAX_TOKENS,
            temperature=0.2
        )

        return self.tokenizer.decode(out[0], skip_special_tokens=True)