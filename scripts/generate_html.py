# scripts/generate_html.py
import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

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
    "securelists":  "Kaspersky Securelist",
    "malwarebytes": "Malwarebytes",
}


def badge(severity: str) -> str:
    return f'<span class="badge sev-{severity.lower()}">{severity}</span>'


def source_badge(source: str) -> str:
    label = SOURCE_LABEL.get(source, source)
    return f'<span class="src-badge">{label}</span>'


def format_dt(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso


def render_advisory_row(item: dict) -> str:
    sev  = item.get("severity", "UNKNOWN")
    title = item.get("title", "")[:120]
    link  = item.get("link", "#")
    pub   = format_dt(item.get("published", ""))
    src   = item.get("source", "")
    summ  = item.get("summary", "")[:300]

    return f"""      <tr class="advisory-row" data-severity="{sev.lower()}" data-source="{src}">
        <td><div class="sev-bar sev-{sev.lower()}"></div></td>
        <td>
          <a href="{link}" target="_blank" rel="noopener" class="advisory-link">{title}</a>
          <div class="summary">{summ}</div>
        </td>
        <td>{badge(sev)}</td>
        <td>{source_badge(src)}</td>
        <td class="dt">{pub}</td>
      </tr>"""


def render_intel_row(item: dict) -> str:
    title = item.get("title", "")[:120]
    link  = item.get("link", "#")
    pub   = format_dt(item.get("published", ""))
    src   = item.get("source", "")
    summ  = item.get("summary", "")[:300]

    return f"""      <tr class="intel-row" data-source="{src}">
        <td>
          <a href="{link}" target="_blank" rel="noopener" class="advisory-link">{title}</a>
          <div class="summary">{summ}</div>
        </td>
        <td>{source_badge(src)}</td>
        <td class="dt">{pub}</td>
      </tr>"""


def render_stat_cards(items: list[dict]) -> str:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in items:
        s = item.get("severity", "UNKNOWN")
        if s in counts:
            counts[s] += 1
    cards = ""
    for sev, count in counts.items():
        cards += (
            f'<div class="sc sc-{sev.lower()}">'
            f'<div class="sc-n">{count}</div>'
            f'<div class="sc-l">{sev}</div>'
            f'</div>'
        )
    return cards


def generate(advisories: list[dict], threat_intel: list[dict], hours: int) -> str:
    advisories.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 4),
            x.get("published", "")
        )
    )
    threat_intel.sort(key=lambda x: x.get("published", ""), reverse=True)

    adv_rows   = "".join(render_advisory_row(i) for i in advisories)
    intel_rows = "".join(render_intel_row(i) for i in threat_intel)
    cards      = render_stat_cards(advisories)
    now        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_adv  = len(advisories)
    total_intel = len(threat_intel)

    sources  = sorted({i.get("source", "") for i in advisories})
    src_opts = "\n".join(
        f'<option value="{s}">{SOURCE_LABEL.get(s, s)}</option>'
        for s in sources
    )

    intel_sources  = sorted({i.get("source", "") for i in threat_intel})
    intel_src_opts = "\n".join(
        f'<option value="{s}">{SOURCE_LABEL.get(s, s)}</option>'
        for s in intel_sources
    )

    return f"""<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Advisory Feed</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:      #f0f4f8;
      --surface: #ffffff;
      --surface2:#e8edf3;
      --border:  #d1d9e0;
      --text:    #1a2332;
      --muted:   #64748b;
      --accent:  #2563eb;
      --radius:  8px;
    }}

    html, body {{
      width: 100%;
      overflow-x: hidden;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', system-ui, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      min-height: 100vh;
    }}

    .topbar {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 28px;
      height: 64px;
      display: flex;
      align-items: center;
      gap: 14px;
      position: sticky;
      top: 0;
      z-index: 10;
      width: 100%;
    }}
    .logo {{
      font-size: 26px;
      font-weight: 600;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 10px;
      flex: 1;
    }}
    .logo-accent {{ color: var(--accent); }}
    .topbar-meta {{
      color: var(--muted);
      font-size: 12px;
      display: flex;
      align-items: center;
      gap: 6px;
      white-space: nowrap;
    }}
    .live-dot {{
      width: 7px; height: 7px;
      border-radius: 50%;
      background: #22c55e;
      display: inline-block;
      animation: pulse 2s ease-in-out infinite;
    }}
    @keyframes pulse {{ 0%,100% {{ opacity:1; }} 50% {{ opacity:.35; }} }}

    .page {{ padding: 20px 28px; width: 100%; }}

    .stat-row {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 16px;
    }}
    .sc {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 9px 14px;
      border-top: 2px solid transparent;
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }}
    .sc-critical {{ border-top-color: #dc2626; }}
    .sc-high     {{ border-top-color: #ea580c; }}
    .sc-medium   {{ border-top-color: #ca8a04; }}
    .sc-low      {{ border-top-color: #16a34a; }}
    .sc-n {{ font-size: 22px; font-weight: 600; color: var(--text); line-height: 1; flex-shrink: 0; }}
    .sc-l {{ font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }}

    .panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      width: 100%;
      margin-bottom: 20px;
    }}
    .panel-header {{
      padding: 11px 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .panel-title {{ font-size: 13px; font-weight: 500; color: var(--text); flex: 1; }}
    .panel-subtitle {{ font-size: 11px; color: var(--muted); }}

    .record-pill {{
      font-size: 11px;
      font-weight: 500;
      padding: 2px 9px;
      border-radius: 99px;
      white-space: nowrap;
    }}
    .pill-blue   {{ background: #eff6ff; color: #2563eb; }}
    .pill-purple {{ background: #f5f3ff; color: #7c3aed; }}

    .filters {{
      padding: 8px 16px;
      border-bottom: 1px solid var(--border);
      display: flex;
      gap: 10px;
      align-items: center;
      background: var(--surface2);
      flex-wrap: wrap;
    }}
    .filter-group {{ display: flex; align-items: center; gap: 6px; }}
    .filter-group label {{ font-size: 11px; font-weight: 500; color: var(--muted); }}
    select, input[type=search] {{
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 5px;
      padding: 4px 8px;
      font-size: 12px;
      font-family: inherit;
      outline: none;
    }}
    select:focus, input[type=search]:focus {{ border-color: var(--accent); }}

    .table-wrap {{ width: 100%; overflow: hidden; }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    col.col-bar  {{ width: 20px; }}
    col.col-sev  {{ width: 90px; }}
    col.col-src  {{ width: 130px; }}
    col.col-date {{ width: 130px; }}

    thead th {{
      text-align: left;
      padding: 7px 12px;
      font-size: 10px;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--muted);
      background: var(--surface2);
      border-bottom: 1px solid var(--border);
    }}
    tbody tr {{ border-bottom: 1px solid var(--border); }}
    tbody tr:last-child {{ border-bottom: none; }}
    tbody tr:hover {{ background: #f8fafc; }}
    tbody tr.hidden {{ display: none; }}
    td {{ padding: 9px 12px; vertical-align: top; overflow: hidden; }}
    td:first-child {{ padding: 0; padding-top: 11px; padding-left: 10px; }}

    .sev-bar {{ width: 3px; height: 30px; border-radius: 99px; }}
    .sev-critical {{ background: #dc2626; }}
    .sev-high     {{ background: #ea580c; }}
    .sev-medium   {{ background: #ca8a04; }}
    .sev-low      {{ background: #16a34a; }}
    .sev-unknown  {{ background: #94a3b8; }}

    .advisory-link {{
      color: var(--accent);
      text-decoration: none;
      font-size: 12px;
      font-weight: 500;
      display: block;
      margin-bottom: 2px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}
    .advisory-link:hover {{ text-decoration: underline; }}
    .summary {{
      color: var(--muted);
      font-size: 11px;
      line-height: 1.5;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }}

    .badge {{
      display: inline-block;
      padding: 2px 7px;
      border-radius: 99px;
      font-size: 10px;
      font-weight: 600;
      white-space: nowrap;
    }}
    .badge.sev-critical {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
    .badge.sev-high     {{ background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }}
    .badge.sev-medium   {{ background: #fefce8; color: #a16207; border: 1px solid #fde68a; }}
    .badge.sev-low      {{ background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }}
    .badge.sev-unknown  {{ background: #f8fafc; color: #64748b; border: 1px solid #e2e8f0; }}

    .src-badge {{
      display: inline-block;
      background: var(--surface2);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 10px;
      font-weight: 500;
      padding: 2px 7px;
      border-radius: 5px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 100%;
    }}

    .dt {{
      color: var(--muted);
      font-size: 11px;
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
    }}

    .empty {{ text-align: center; padding: 40px; color: var(--muted); }}

    footer {{
      margin-top: 20px;
      color: var(--muted);
      font-size: 11px;
      display: flex;
      gap: 14px;
      flex-wrap: wrap;
      align-items: center;
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}
    footer a:hover {{ text-decoration: underline; }}

    @media (max-width: 640px) {{
      .topbar, .page {{ padding-left: 14px; padding-right: 14px; }}
      .stat-row {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    }}
  </style>
</head>
<body>

<div class="topbar">
  <div class="logo">
    <svg width="24" height="24" viewBox="0 0 16 16" fill="none">
      <path d="M8 1.5L14 4.5V11.5L8 14.5L2 11.5V4.5L8 1.5Z" stroke="#2563eb" stroke-width="1.2" fill="rgba(37,99,235,.08)"/>
      <path d="M8 5V11M5.5 6.5L8 5L10.5 6.5" stroke="#2563eb" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    Security <span class="logo-accent">Feed</span>
  </div>
  <div class="topbar-meta">
    <span class="live-dot"></span>
    {now} &nbsp;·&nbsp; okno {hours} h
  </div>
</div>

<div class="page">

  <div class="stat-row">
    {cards}
  </div>

  <!-- CVE Advisories panel -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Bezpečnostní advisories</span>
      <span class="panel-subtitle">CVE · strukturované záznamy</span>
      <span class="record-pill pill-blue" id="adv-count">{total_adv} záznamů</span>
    </div>
    <div class="filters">
      <div class="filter-group">
        <label>Závažnost</label>
        <select id="f-sev" onchange="applyAdvisoryFilters()">
          <option value="">Vše</option>
          <option value="critical">CRITICAL</option>
          <option value="high">HIGH</option>
          <option value="medium">MEDIUM</option>
          <option value="low">LOW</option>
        </select>
      </div>
      <div class="filter-group">
        <label>Zdroj</label>
        <select id="f-src" onchange="applyAdvisoryFilters()">
          <option value="">Vše</option>
          {src_opts}
        </select>
      </div>
      <div class="filter-group">
        <label>Hledat</label>
        <input type="search" id="f-search" placeholder="CVE-…, klíčové slovo" oninput="applyAdvisoryFilters()">
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <colgroup>
          <col class="col-bar">
          <col>
          <col class="col-sev">
          <col class="col-src">
          <col class="col-date">
        </colgroup>
        <thead>
          <tr>
            <th></th>
            <th>Advisory</th>
            <th>Závažnost</th>
            <th>Zdroj</th>
            <th>Publikováno</th>
          </tr>
        </thead>
        <tbody id="adv-tbody">
          {adv_rows}
        </tbody>
      </table>
      <div class="empty" id="adv-empty" style="display:none">Žádné záznamy neodpovídají filtru.</div>
    </div>
  </div>

  <!-- Threat Intel panel -->
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Threat Intelligence</span>
      <span class="panel-subtitle">CrowdStrike · Sophos · Malwarebytes</span>
      <span class="record-pill pill-purple" id="intel-count">{total_intel} záznamů</span>
    </div>
    <div class="filters">
      <div class="filter-group">
        <label>Zdroj</label>
        <select id="f-intel-src" onchange="applyIntelFilters()">
          <option value="">Vše</option>
          {intel_src_opts}
        </select>
      </div>
      <div class="filter-group">
        <label>Hledat</label>
        <input type="search" id="f-intel-search" placeholder="klíčové slovo…" oninput="applyIntelFilters()">
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <colgroup>
          <col>
          <col class="col-src">
          <col class="col-date">
        </colgroup>
        <thead>
          <tr>
            <th>Článek</th>
            <th>Zdroj</th>
            <th>Publikováno</th>
          </tr>
        </thead>
        <tbody id="intel-tbody">
          {intel_rows}
        </tbody>
      </table>
      <div class="empty" id="intel-empty" style="display:none">Žádné záznamy neodpovídají filtru.</div>
    </div>
  </div>

  <footer>
    <span>CVE zdroje: MSRC · CISA KEV · NVD · Cisco · Red Hat · VMware · Ubuntu · Debian · Mozilla · Chrome · Fortinet · Palo Alto</span>
    <a href="data.json">data.json</a>
    <a href="https://github.com/Bublays/Security_feed">GitHub</a>
  </footer>

</div>

<script>
  function applyAdvisoryFilters() {{
    const sev    = document.getElementById('f-sev').value;
    const src    = document.getElementById('f-src').value;
    const search = document.getElementById('f-search').value.toLowerCase();
    const rows   = document.querySelectorAll('#adv-tbody .advisory-row');
    let visible  = 0;
    rows.forEach(row => {{
      const show = (!sev    || row.dataset.severity === sev)
                && (!src    || row.dataset.source   === src)
                && (!search || row.textContent.toLowerCase().includes(search));
      row.classList.toggle('hidden', !show);
      if (show) visible++;
    }});
    document.getElementById('adv-count').textContent = visible + ' záznamů';
    document.getElementById('adv-empty').style.display = visible === 0 ? 'block' : 'none';
  }}

  function applyIntelFilters() {{
    const src    = document.getElementById('f-intel-src').value;
    const search = document.getElementById('f-intel-search').value.toLowerCase();
    const rows   = document.querySelectorAll('#intel-tbody .intel-row');
    let visible  = 0;
    rows.forEach(row => {{
      const show = (!src    || row.dataset.source === src)
                && (!search || row.textContent.toLowerCase().includes(search));
      row.classList.toggle('hidden', !show);
      if (show) visible++;
    }});
    document.getElementById('intel-count').textContent = visible + ' záznamů';
    document.getElementById('intel-empty').style.display = visible === 0 ? 'block' : 'none';
  }}
</script>

</body>
</html>"""


def main():
    src = Path("output/advisories.json")
    if not src.exists():
        print("output/advisories.json nenalezen")
        return

    all_items  = json.loads(src.read_text())
    advisories = [i for i in all_items if i.get("category") == "advisory"]
    threat_intel = [i for i in all_items if i.get("category") == "threat_intel"]

    # Zpětná kompatibilita — záznamy bez category považujeme za advisory
    no_cat = [i for i in all_items if "category" not in i]
    advisories += no_cat

    docs = Path("docs")
    docs.mkdir(exist_ok=True)

    (docs / "data.json").write_text(
        json.dumps(all_items, ensure_ascii=False, indent=2)
    )

    # Zjistíme hours z dat (fallback 48)
    hours = 48
    html = generate(advisories, threat_intel, hours)
    (docs / "index.html").write_text(html, encoding="utf-8")
    print(f"Vygenerováno docs/index.html")
    print(f"  Advisories:   {len(advisories)}")
    print(f"  Threat intel: {len(threat_intel)}")


if __name__ == "__main__":
    main()
