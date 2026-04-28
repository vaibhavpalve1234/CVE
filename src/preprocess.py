import json, glob
from tqdm import tqdm

def extract(entry):
    try:
        cve_id = entry["cve"]["id"]
        desc = entry["cve"]["descriptions"][0]["value"]

        severity = "UNKNOWN"
        if "metrics" in entry and "cvssMetricV31" in entry["metrics"]:
            severity = entry["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

        return {"cve_id": cve_id, "description": desc, "severity": severity}
    except:
        return None

def process():
    dataset = []
    for f in tqdm(glob.glob("data/raw/*.json")):
        data = json.load(open(f))
        for item in data["vulnerabilities"]:
            c = extract(item["cve"])
            if c:
                dataset.append(c)

    json.dump(dataset, open("data/processed/cve_dataset.json","w"), indent=2)

if __name__ == "__main__":
    process()