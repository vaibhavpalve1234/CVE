from src.rag_pipeline import CVERag

rag = CVERag()

queries = [
    ("Log4j", "CVE-2021-44228"),
]

correct = 0

for q, expected in queries:
    res = rag.ask(q)
    if res.get("cve_id") == expected:
        correct += 1

print("Accuracy:", correct/len(queries))