import argparse
import json
import os
import time
from datetime import datetime, timezone

import requests
from tqdm import tqdm

RHEL_CVE_LIST_URL = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
RHEL_CVE_DETAIL_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"


def utc_iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_cve_page(page, per_page, after=None, before=None):
    params = {
        "page": page,
        "per_page": per_page,
    }
    if after:
        params["after"] = after
    if before:
        params["before"] = before

    resp = requests.get(RHEL_CVE_LIST_URL, params=params, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list):
        raise ValueError("Unexpected response from Red Hat CVE list endpoint")
    return data


def fetch_cve_details(cve_id):
    url = RHEL_CVE_DETAIL_URL.format(cve_id=cve_id)
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.json()


def fetch_all(output_path, per_page=1000, delay=0.2, after=None, before=None, with_details=False):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    records = []
    page = 1

    while True:
        page_items = fetch_cve_page(page=page, per_page=per_page, after=after, before=before)
        if not page_items:
            break

        records.extend(page_items)
        print(f"Fetched page {page} with {len(page_items)} CVEs (running total: {len(records)})")
        page += 1
        time.sleep(delay)

    if with_details:
        detailed = []
        pbar = tqdm(records, desc="Fetching Red Hat CVE details", unit="cve")
        for item in pbar:
            cve_id = item.get("CVE") or item.get("name")
            if not cve_id:
                continue
            try:
                detail = fetch_cve_details(cve_id)
            except Exception:
                # fallback to list item if detail endpoint fails for some records
                detail = item
            detailed.append(detail)
            time.sleep(delay)
        records = detailed

    output = {
        "format": "RHEL_CVE",
        "version": "1.0",
        "timestamp": utc_iso_now(),
        "totalResults": len(records),
        "vulnerabilities": records,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Saved {len(records)} Red Hat CVE records to {output_path}")


def parse_args():
    parser = argparse.ArgumentParser(description="Download CVE data from Red Hat security data API")
    parser.add_argument("--output", default="data/raw/rhel_cves_all.json", help="Output JSON path")
    parser.add_argument("--per-page", type=int, default=1000, help="Page size for list API")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests")
    parser.add_argument("--after", help="Optional lower date bound (YYYY-MM-DD)")
    parser.add_argument("--before", help="Optional upper date bound (YYYY-MM-DD)")
    parser.add_argument(
        "--with-details",
        action="store_true",
        help="Fetch per-CVE detail JSON for each CVE in the list (slower but richer)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    fetch_all(
        output_path=args.output,
        per_page=max(1, args.per_page),
        delay=max(0.0, args.delay),
        after=args.after,
        before=args.before,
        with_details=args.with_details,
    )


if __name__ == "__main__":
    main()
