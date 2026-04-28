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


def extract(vulnerability_entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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
        }
    except Exception:
        return None


def process(raw_pattern: str = "data/raw/*.json", output_path: str = "data/processed/cve_dataset.json"):
    dataset = []

    for file_path in tqdm(glob.glob(raw_pattern), desc="Processing raw CVE files"):
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        vulnerabilities = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            parsed = extract(item)
            if parsed:
                dataset.append(parsed)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"Saved {len(dataset)} processed CVEs -> {output_path}")


if __name__ == "__main__":
    process()
