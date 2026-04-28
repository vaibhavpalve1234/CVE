import argparse
import json
import os
import time
from datetime import datetime, timezone

import requests
from tqdm import tqdm

NVD_V2_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def utc_iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_page(start_index, results_per_page, api_key=None, modified_start=None, modified_end=None):
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page,
    }

    if modified_start:
        params["lastModStartDate"] = modified_start
    if modified_end:
        params["lastModEndDate"] = modified_end

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(NVD_V2_ENDPOINT, params=params, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def fetch_all(output_path, api_key=None, results_per_page=2000, delay=1.2, modified_start=None, modified_end=None):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    all_vulns = []
    start_index = 0
    total_results = None

    pbar = tqdm(total=0, desc="Downloading NVD CVE 2.0", unit="cve")

    while total_results is None or start_index < total_results:
        payload = fetch_page(
            start_index=start_index,
            results_per_page=results_per_page,
            api_key=api_key,
            modified_start=modified_start,
            modified_end=modified_end,
        )

        vulnerabilities = payload.get("vulnerabilities", [])
        total_results = payload.get("totalResults", len(vulnerabilities))

        if pbar.total != total_results:
            pbar.total = total_results
            pbar.refresh()

        all_vulns.extend(vulnerabilities)
        pbar.update(len(vulnerabilities))

        start_index += len(vulnerabilities)
        if len(vulnerabilities) == 0:
            break

        time.sleep(delay)

    pbar.close()

    output = {
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": utc_iso_now(),
        "totalResults": len(all_vulns),
        "vulnerabilities": all_vulns,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Saved {len(all_vulns)} vulnerabilities to {output_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Download CVE data from NVD API v2.0")
    parser.add_argument("--output", default="data/raw/nvd_cves_v2.json", help="Path to output JSON file")
    parser.add_argument("--api-key", default=os.getenv("NVD_API_KEY"), help="NVD API key (or set NVD_API_KEY)")
    parser.add_argument("--results-per-page", type=int, default=2000, help="Page size (max 2000)")
    parser.add_argument("--delay", type=float, default=1.2, help="Delay between API calls in seconds")
    parser.add_argument("--last-mod-start", help="Filter start (ISO-8601, e.g. 2026-01-01T00:00:00.000)")
    parser.add_argument("--last-mod-end", help="Filter end (ISO-8601, e.g. 2026-01-31T23:59:59.000)")
    return parser.parse_args()


def main():
    args = parse_args()
    fetch_all(
        output_path=args.output,
        api_key=args.api_key,
        results_per_page=min(args.results_per_page, 2000),
        delay=max(args.delay, 0.0),
        modified_start=args.last_mod_start,
        modified_end=args.last_mod_end,
    )


if __name__ == "__main__":
    main()
