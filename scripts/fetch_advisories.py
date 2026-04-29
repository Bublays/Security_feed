# scripts/fetch_advisories.py
import argparse, json, os, sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests

SOURCES = {
    "msrc": "https://api.msrc.microsoft.com/update-guide/rss",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "cisco": "https://sec.cloudapps.cisco.com/security/center/psirtrss20.xml",
    "redhat": "https://access.redhat.com/security/all-advisories.rss",
    "vmware": "https://www.vmware.com/security/advisories/rss.xml",
}

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--hours", type=int, default=72)
    return p.parse_args()

def fetch_rss(name: str, url: str, since: datetime) -> list[dict]:
    feed = feedparser.parse(url)
    items = []
    for entry in feed.entries:
        # feedparser normalizuje datum do published_parsed (time.struct_time)
        if hasattr(entry, "published_parsed") and entry.published_parsed:
            pub = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        else:
            pub = datetime.now(timezone.utc)  # fallback

        if pub < since:
            continue

        items.append({
            "source":      name,
            "id":          entry.get("id", entry.get("link", "")),
            "title":       entry.get("title", ""),
            "link":        entry.get("link", ""),
            "published":   pub.isoformat(),
            "summary":     entry.get("summary", "")[:500],
            "severity":    extract_severity(entry),
        })
    return items

def fetch_cisa_kev(since: datetime) -> list[dict]:
    """CISA KEV je JSON, ne RSS."""
    url = SOURCES["cisa_kev"]
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    items = []
    for vuln in data.get("vulnerabilities", []):
        date_added = datetime.fromisoformat(
            vuln.get("dateAdded", "1970-01-01")
        ).replace(tzinfo=timezone.utc)
        if date_added < since:
            continue
        items.append({
            "source":    "cisa_kev",
            "id":        vuln.get("cveID", ""),
            "title":     f"{vuln['cveID']} – {vuln.get('vulnerabilityName', '')}",
            "link":      f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published": date_added.isoformat(),
            "summary":   vuln.get("shortDescription", "")[:500],
            "severity":  "CRITICAL",  # KEV = aktivně zneužívané
        })
    return items

def fetch_nvd(since: datetime) -> list[dict]:
    """NVD REST API v2 — vyžaduje API klíč pro vyšší rate limit."""
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    pub_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?pubStartDate={pub_start}&pubEndDate={pub_end}&resultsPerPage=100"
    )
    r = requests.get(url, headers=headers, timeout=60)
    r.raise_for_status()
    items = []
    for vuln in r.json().get("vulnerabilities", []):
        cve = vuln["cve"]
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
            "id":        cve["id"],
            "title":     f"{cve['id']} (CVSS {score})",
            "link":      f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            "published": cve.get("published", ""),
            "summary":   desc[:500],
            "severity":  cvss_to_severity(score),
        })
    return items

def extract_severity(entry) -> str:
    """Pokus o extrakci závažnosti z RSS záznamu."""
    title = entry.get("title", "").upper()
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if s in title:
            return s
    return "UNKNOWN"

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
    args = parse_args()
    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    print(f"Fetching advisories since {since.isoformat()} ({args.hours}h window)")

    all_items: list[dict] = []

    # RSS zdroje
    for name, url in SOURCES.items():
        if name == "cisa_kev":
            continue
        try:
            items = fetch_rss(name, url, since)
            print(f"  {name}: {len(items)} položek")
            all_items.extend(items)
        except Exception as e:
            print(f"  WARN {name}: {e}", file=sys.stderr)

    # CISA KEV (JSON)
    try:
        items = fetch_cisa_kev(since)
        print(f"  cisa_kev: {len(items)} položek")
        all_items.extend(items)
    except Exception as e:
        print(f"  WARN cisa_kev: {e}", file=sys.stderr)

    # NVD (volitelné – může být pomalé)
    try:
        items = fetch_nvd(since)
        print(f"  nvd: {len(items)} položek")
        all_items.extend(items)
    except Exception as e:
        print(f"  WARN nvd: {e}", file=sys.stderr)

    all_items = deduplicate(all_items)
    all_items.sort(key=lambda x: x["published"], reverse=True)

    Path("output").mkdir(exist_ok=True)
    out_path = Path("output/advisories.json")
    out_path.write_text(json.dumps(all_items, ensure_ascii=False, indent=2))
    print(f"Celkem: {len(all_items)} unikátních záznamů → {out_path}")

if __name__ == "__main__":
    main()
