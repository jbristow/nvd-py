import json


def extract_type(weaknesses):
    output = []
    for weakness in weaknesses:
        for description in weakness.get("description", []):
            if description.get("lang") == "en":
                output.append({"type": weakness["type"], "cwe": description["value"]})
    return output


def extract_severity(metrics):
    output = []
    if "cvssMetricV40" in metrics:
        for metric in metrics["cvssMetricV40"]:
            output.append(
                {"type": metric["type"], "severity": metric["cvssData"]["baseSeverity"]}
            )
    if "cvssMetricV30" in metrics:
        for metric in metrics["cvssMetricV30"]:
            output.append(
                {"type": metric["type"], "severity": metric["cvssData"]["baseSeverity"]}
            )
    if "cvssMetricV31" in metrics:
        for metric in metrics["cvssMetricV31"]:
            output.append(
                {"type": metric["type"], "severity": metric["cvssData"]["baseSeverity"]}
            )
    if "cvssMetricV2" in metrics:
        for metric in metrics["cvssMetricV2"]:
            output.append({"type": metric["type"], "severity": metric["baseSeverity"]})
    return output


def extract_kev(cve):
    return all(
        k in cve
        for k in [
            "cisaExploitAdd",
            "cisaActionDue",
            "cisaRequiredAction",
            "cisaVulnerabilityName",
        ]
    )


def summarize(vuln):
    cve = vuln["cve"]

    return {
        "id": cve["id"],
        "published": cve["published"],
        "lastModified": cve["lastModified"],
        "types": extract_type(cve.get("weaknesses", [])),
        "severities": extract_severity(cve.get("metrics", {})),
        "has_kev": extract_kev(cve),
    }


def summarize_and_write(vulns: list, fname: str):
    output = [summarize(vuln) for vuln in vulns]
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(output, f, separators=(",", ":"))
