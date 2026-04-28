import glob
import json
import os
from typing import Any, Dict, List, Optional

from tqdm import tqdm


def pick_english_description(descriptions: List[Dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def parse_severity_and_score(metrics: Dict[str, Any]) -> Dict[str, Optional[Any]]:
    metric_keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

    for key in metric_keys:
        items = metrics.get(key, [])
        if not items:
            continue

        cvss = items[0].get("cvssData", {})
        severity = cvss.get("baseSeverity") or items[0].get("baseSeverity") or "UNKNOWN"
        score = cvss.get("baseScore")
        vector = cvss.get("vectorString")

        return {
            "severity": severity,
            "cvss_score": score,
            "cvss_vector": vector,
        }

    return {
        "severity": "UNKNOWN",
        "cvss_score": None,
        "cvss_vector": None,
    }


def extract_nvd_v2(vulnerability_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        cve = vulnerability_entry.get("cve", {})
        cve_id = cve["id"]

        description = pick_english_description(cve.get("descriptions", []))
        metric_info = parse_severity_and_score(cve.get("metrics", {}))

        references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value"):
                    weaknesses.append(desc["value"])

        return {
            "cve_id": cve_id,
            "description": description,
            "severity": metric_info["severity"],
            "cvss_score": metric_info["cvss_score"],
            "cvss_vector": metric_info["cvss_vector"],
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "references": references,
            "weaknesses": weaknesses,
            "source": "nvd",
        }
    except Exception:
        return None


def extract_rhel(vulnerability_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cve_id = vulnerability_entry.get("name") or vulnerability_entry.get("CVE")
    if not cve_id:
        return None

    details = vulnerability_entry.get("details")
    description = ""
    if isinstance(details, list) and details:
        description = details[0]
    elif isinstance(details, str):
        description = details

    cvss3 = vulnerability_entry.get("cvss3", {})
    cvss2 = vulnerability_entry.get("cvss", {})
    score = cvss3.get("cvss3_base_score") or cvss2.get("cvss_base_score")
    vector = cvss3.get("cvss3_scoring_vector") or cvss2.get("cvss_scoring_vector")

    references = []
    if vulnerability_entry.get("references"):
        references = [r.strip() for r in vulnerability_entry["references"].split() if r.strip()]

    return {
        "cve_id": cve_id,
        "description": description,
        "severity": vulnerability_entry.get("threat_severity", "UNKNOWN"),
        "cvss_score": score,
        "cvss_vector": vector,
        "published": vulnerability_entry.get("public_date"),
        "last_modified": vulnerability_entry.get("bugzilla", {}).get("last_modified")
        if isinstance(vulnerability_entry.get("bugzilla"), dict)
        else None,
        "references": references,
        "weaknesses": [],
        "source": "rhel",
    }


def parse_file(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    vulnerabilities = data.get("vulnerabilities", [])
    parsed = []

    fmt = str(data.get("format", "")).upper()
    if fmt == "RHEL_CVE":
        for item in vulnerabilities:
            record = extract_rhel(item)
            if record:
                parsed.append(record)
        return parsed

    for item in vulnerabilities:
        record = extract_nvd_v2(item)
        if record:
            parsed.append(record)

    return parsed


def deduplicate(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}

    for record in records:
        cve_id = record.get("cve_id")
        if not cve_id:
            continue

        if cve_id not in by_id:
            by_id[cve_id] = record
            continue

        existing = by_id[cve_id]
        existing_refs = set(existing.get("references", []))
        merged_refs = list(existing_refs.union(record.get("references", [])))

        existing["references"] = merged_refs
        if not existing.get("description") and record.get("description"):
            existing["description"] = record["description"]
        if existing.get("severity", "UNKNOWN") == "UNKNOWN" and record.get("severity"):
            existing["severity"] = record["severity"]
        if not existing.get("cvss_score") and record.get("cvss_score"):
            existing["cvss_score"] = record["cvss_score"]
        if not existing.get("cvss_vector") and record.get("cvss_vector"):
            existing["cvss_vector"] = record["cvss_vector"]

        sources = {existing.get("source", "unknown"), record.get("source", "unknown")}
        existing["source"] = "+".join(sorted(s for s in sources if s))

    return list(by_id.values())


def process(raw_pattern: str = "data/raw/*.json", output_path: str = "data/processed/cve_dataset.json"):
    records = []

    for file_path in tqdm(glob.glob(raw_pattern), desc="Processing raw CVE files"):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        parsed = parse_file(data)
        records.extend(parsed)

    dataset = deduplicate(records)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"Saved {len(dataset)} processed CVEs -> {output_path}")


if __name__ == "__main__":
    process()
