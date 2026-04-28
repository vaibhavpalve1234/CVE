import json

class JSONGuard:
    def extract(self, text):
        try:
            start = text.find("{")
            end = text.rfind("}")
            return json.loads(text[start:end+1])
        except:
            return None

    def enforce(self, model, prompt):
        for _ in range(2):
            out = model.generate(prompt)
            parsed = self.extract(out)
            if parsed:
                return parsed
        return {"error": "invalid"}