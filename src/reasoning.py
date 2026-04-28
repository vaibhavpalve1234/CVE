class CVEReasoner:
    def analyze(self, cve):
        desc = cve["description"].lower()

        return {
            "attack_vector": "NETWORK" if "remote" in desc else "LOCAL",
            "impact": "HIGH" if "execute" in desc else "MEDIUM",
            "mitigation": "Patch immediately"
        }