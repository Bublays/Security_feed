# scripts/fetch_advisories.py
import argparse, json, os, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests

# ── Strukturované CVE advisory zdroje ─────────────────────────────────────────
CVE_SOURCES = {
    "msrc":     "https://api.msrc.microsoft.com/update-guide/rss",
    "cisco":    "https://sec.cloudapps.cisco.com/security/center/psirtrss20.xml",
    "redhat":   "https://access.redhat.com/security/all-advisories.rss",
    "vmware":   "https://www.vmware.com/security/advisories/rss.xml",
    "ubuntu":   "https://ubuntu.com/security/notices/rss.xml",
    "debian":   "https://www.debian.org/security/dsa.en.rdf",
    "mozilla":  "https://www.mozilla.org/en-US/security/advisories/feed/",
    "google":   "https://chromereleases.googleblog.com/feeds/posts/default",
    "fortinet": "https://www.fortiguard.com/rss/ir.xml",
    "paloalto": "https://security.paloaltonetworks.com/rss.xml",
}

# ── Threat intelligence zdroje ────────────────────────────────────────────────
THREAT_INTEL_SOURCES = {
    "crowdstrike":  "https://www.crowdstrike.com/blog/feed/",
    "securelist":   "https://securelist.com/feed/",
    "malwarebytes": "https://www.malwarebytes.com/blog/feed",
}

# Klíčová slova pro filtrování zdrojů s vysokým objemem článků
THREAT_INTEL_KEYWORDS = {
    "crowdstrike": [
        "vulnerability", "cve", "exploit", "ransomware", "malware",
        "attack", "threat", "breach", "zero-day", "zero day",
        "campaign", "advisory", "patch", "backdoor", "trojan",
        "phishing", "intrusion", "incident",
    ],
    "securelist":   [],  # Securelist je čistě security — bez filtru
    "malwarebytes": [],  # Malwarebytes také — bez filtru
}

SOURCE_LABEL = {
    "msrc":         "Microsoft MSRC",
    "cisa_kev":     "CISA KEV",
    "nvd":          "NVD",
    "cisco":        "Cisco",
    "redhat":       "Red Hat",
    "vmware":       "VMware",
    "ubuntu":       "Ubuntu",
    "debian":       "Debian",
    "mozilla":      "Mozilla",
    "google":       "Google Chrome",
    "fortinet":     "Fortinet",
    "paloalto":     "Palo Alto",
    "crowdstrike":  "CrowdStrike",
    "securelist":   "Kaspersky Securelist",
    "malwarebytes": "Malwarebytes",
}


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--hours", type=int, default=48)
    return p.parse_args()


def parse_date(entry) -> datetime:
    for field in ("published_parsed", "updated_parsed", "created_parsed"):
        val = getattr(entry, field, None)
        if val:
            try:
                return datetime(*val[:6], tzinfo=timezone.utc)
            except Exception:
                continue
    return datetime.now(timezone.utc)


def extract_severity(entry, source: str) -> str:
    text = (entry.get("title", "") + " " + entry.get("summary", "")).upper()
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s in text:
            return s
    if source in ("cisa_kev", "fortinet", "paloalto"):
        return "HIGH"
    return "UNKNOWN"


def is_relevant_intel(entry: dict, source: str) -> bool:
    keywords = THREAT_INTEL_KEYWORDS.get(source, [])
    if not keywords:
        return True
    text = (entry.get("title", "") + " " + entry.get("summary", "")).lower()
    return any(kw in text for kw in keywords)


def fetch_rss(name: str, url: str, since: datetime,
              category: str = "advisory") -> list[dict]:
    try:
        feed = feedparser.parse(url)
    except Exception as e:
        print(f"  ERR {name}: {e}", file=sys.stderr)
        return []

    print(f"  {name}: celkem {len(feed.entries)} entries v RSS")
    items = []
    skipped = 0
    for entry in feed.entries:
        pub = parse_date(entry)
        if pub < since:
            continue

        # Filtr relevance pro threat intel zdroje
        if category == "threat_intel" and not is_relevant_intel(entry, name):
            skipped += 1
            continue

        items.append({
            "source":    name,
            "category":  category,
            "id":        entry.get("id") or entry.get("link", ""),
            "title":     entry.get("title", "")[:255],
            "link":      entry.get("link", ""),
            "published": pub.isoformat(),
            "summary":   entry.get("summary", "")[:500],
            "severity":  extract_severity(entry, name),
        })

    if skipped:
        print(f"  {name}: {len(items)} položek v okně ({skipped} filtrováno jako nerelevantní)")
    else:
        print(f"  {name}: {len(items)} položek v okně")
    return items


def fetch_cisa_kev(since: datetime) -> list[dict]:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"  ERR cisa_kev: {e}", file=sys.stderr)
        return []

    items = []
    for vuln in data.get("vulnerabilities", []):
        try:
            date_added = datetime.fromisoformat(
                vuln.get("dateAdded", "1970-01-01")
            ).replace(tzinfo=timezone.utc)
        except Exception:
            continue

        if date_added < since:
            continue

        items.append({
            "source":    "cisa_kev",
            "category":  "advisory",
            "id":        vuln.get("cveID", ""),
            "title":     f"{vuln['cveID']} – {vuln.get('vulnerabilityName', '')}",
            "link":      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published": date_added.isoformat(),
            "summary":   vuln.get("shortDescription", "")[:500],
            "severity":  "CRITICAL",
        })

    print(f"  cisa_kev: {len(items)} položek v okně")
    return items


def fetch_nvd(since: datetime) -> list[dict]:
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    pub_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={pub_start}&pubEndDate={pub_end}&resultsPerPage=100"
    )
    try:
        r = requests.get(url, headers=headers, timeout=60)
        r.raise_for_status()
    except Exception as e:
        print(f"  ERR nvd: {e}", file=sys.stderr)
        return []

    items = []
    for vuln in r.json().get("vulnerabilities", []):
        cve  = vuln["cve"]
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
            ""
        )
        metrics = cve.get("metrics", {})
        score = (
            metrics.get("cvssMetricV31", [{}])[0]
            .get("cvssData", {})
            .get("baseScore", "N/A")
            if metrics.get("cvssMetricV31") else "N/A"
        )
        items.append({
            "source":    "nvd",
            "category":  "advisory",
            "id":        cve["id"],
            "title":     f"{cve['id']} (CVSS {score})",
            "link":      f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            "published": cve.get("published", ""),
            "summary":   desc[:500],
            "severity":  cvss_to_severity(score),
        })

    print(f"  nvd: {len(items)} položek v okně")
    return items


def cvss_to_severity(score) -> str:
    try:
        s = float(score)
        if s >= 9.0: return "CRITICAL"
        if s >= 7.0: return "HIGH"
        if s >= 4.0: return "MEDIUM"
        return "LOW"
    except (ValueError, TypeError):
        return "UNKNOWN"


def deduplicate(items: list[dict]) -> list[dict]:
    seen, result = set(), []
    for item in items:
        key = item["id"] or item["link"]
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def main():
    args  = parse_args()
    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    print(f"Fetching advisories since {since.isoformat()} ({args.hours}h window)\n")

    all_items: list[dict] = []

    print("── CVE advisory zdroje ──")
    for name, url in CVE_SOURCES.items():
        items = fetch_rss(name, url, since, category="advisory")
        all_items.extend(items)

    items = fetch_cisa_kev(since)
    all_items.extend(items)

    print("\n── NVD ──")
    items = fetch_nvd(since)
    all_items.extend(items)

    print("\n── Threat intelligence zdroje ──")
    for name, url in THREAT_INTEL_SOURCES.items():
        items = fetch_rss(name, url, since, category="threat_intel")
        all_items.extend(items)

    all_items = deduplicate(all_items)
    all_items.sort(key=lambda x: x.get("published", ""), reverse=True)

    Path("output").mkdir(exist_ok=True)
    out_path = Path("output/advisories.json")
    out_path.write_text(json.dumps(all_items, ensure_ascii=False, indent=2))

    advisories   = [i for i in all_items if i["category"] == "advisory"]
    threat_intel = [i for i in all_items if i["category"] == "threat_intel"]
    print(f"\nCelkem: {len(all_items)} unikátních záznamů → {out_path}")
    print(f"  Advisories:   {len(advisories)}")
    print(f"  Threat intel: {len(threat_intel)}")


if __name__ == "__main__":
    main()
