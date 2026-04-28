import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import argparse
import json
from src.rag_pipeline import CVERag
from src.config import TOP_K


def build_parser():
    parser = argparse.ArgumentParser(
        description="CVE assistant: ask questions or fetch full stored details by CVE ID."
    )
    parser.add_argument(
        "--cve-id",
        help="Return the full stored record for an exact CVE ID (example: CVE-2021-44228).",
    )
    parser.add_argument(
        "--query",
        help="Run one non-interactive query and print JSON response.",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=TOP_K,
        help="How many CVE records to retrieve for each query.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    rag = CVERag()

    if args.cve_id:
        details = rag.get_cve_details(args.cve_id)
        if details is None:
            print(json.dumps({"error": f"{args.cve_id} not found in index metadata"}, indent=2))
            return

        print(json.dumps(details, indent=2))
        return

    if args.query:
        print(rag.ask(args.query, k=args.top_k))
        return

    while True:
        q = input("Ask CVE > ").strip()
        if q.lower() in {"exit", "quit"}:
            break

        print(rag.ask(q, k=args.top_k))


if __name__ == "__main__":
    main()
