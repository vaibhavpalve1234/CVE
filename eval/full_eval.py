from src.rag_pipeline import CVERag

rag = CVERag()

tests = [
    {"query": "Log4Shell vulnerability", "expected": "CVE-2021-44228"},
    {"query": "Zerologon issue", "expected": "CVE-2020-1472"}
]

def evaluate():
    correct = 0

    for t in tests:
        res = rag.ask(t["query"])

        print("\nQuery:", t["query"])
        print("Response:", res)

        if isinstance(res, dict) and res.get("cve_id") == t["expected"]:
            correct += 1

    print("\nAccuracy:", correct / len(tests))

if __name__ == "__main__":
    evaluate()