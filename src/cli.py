from src.rag_pipeline import CVERag

rag = CVERag()

while True:
    q = input("Ask CVE > ")
    if q == "exit":
        break

    print(rag.ask(q))