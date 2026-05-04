# scripts/generate_html.py
import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

SOURCE_LABEL = {
    "msrc":     "Microsoft MSRC",
    "cisa_kev": "CISA KEV",
    "nvd":      "NVD",
    "cisco":    "Cisco",
    "redhat":   "Red Hat",
    "vmware":   "VMware",
}

def badge(severity: str) -> str:
    return f'<span class="badge sev-{severity.lower()}">{severity}</span>'

def source_badge(source: str) -> str:
    label = SOURCE_LABEL.get(source, source)
    return f'<span class="src-badge src-{source}">{label}</span>'

def format_dt(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso

def render_row(item: dict) -> str:
    sev   = item.get("severity", "UNKNOWN")
    title = item.get("title", "")[:120]
    link  = item.get("link", "#")
    pub   = format_dt(item.get("published", ""))
    src   = item.get("source", "")
    summ  = item.get("summary", "")[:300]

    return f"""      <tr class="advisory-row" data-severity="{sev.lower()}" data-source="{src}">
        <td><div class="sev-indicator sev-{sev.lower()}"></div></td>
        <td>
          <a href="{link}" target="_blank" rel="noopener" class="advisory-link">{title}</a>
          <div class="summary">{summ}</div>
        </td>
        <td>{badge(sev)}</td>
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
    icons = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
    }
    for sev, count in counts.items():
        cards += f"""
    <div class="stat-card sev-card-{sev.lower()}">
      <div class="stat-icon">{icons[sev]}</div>
      <div class="stat-count">{count}</div>
      <div class="stat-label">{sev}</div>
    </div>"""
    return cards

def generate(advisories: list[dict]) -> str:
    advisories.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(x.get("severity", "UNKNOWN"), 4),
            x.get("published", "")
        )
    )

    rows  = "".join(render_row(i) for i in advisories)
    cards = render_stat_cards(advisories)
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(advisories)

    sources  = sorted({i.get("source", "") for i in advisories})
    src_opts = "\n".join(
        f'<option value="{s}">{SOURCE_LABEL.get(s, s)}</option>'
        for s in sources
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
      --bg:        #f5f6fa;
      --surface:   #ffffff;
      --surface2:  #f0f1f6;
      --border:    #e2e4ec;
      --text:      #1a1d2e;
      --muted:     #6b7280;
      --accent:    #2563eb;
      --accent-bg: #eff6ff;
      --radius:    10px;
      --shadow:    0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.04);
      --shadow-md: 0 4px 12px rgba(0,0,0,.08);
      --font:      'Inter', system-ui, sans-serif;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }}

    /* ── Top bar ── */
    .topbar {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 32px;
      height: 56px;
      display: flex;
      align-items: center;
      gap: 12px;
      box-shadow: var(--shadow);
      position: sticky;
      top: 0;
      z-index: 10;
    }}
    .topbar-logo {{
      font-size: 18px;
      font-weight: 600;
      color: var(--text);
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .topbar-logo span {{ color: var(--accent); }}
    .topbar-meta {{
      margin-left: auto;
      color: var(--muted);
      font-size: 12px;
    }}
    .live-dot {{
      display: inline-block;
      width: 7px; height: 7px;
      border-radius: 50%;
      background: #22c55e;
      margin-right: 5px;
      animation: pulse 2s ease-in-out infinite;
    }}
    @keyframes pulse {{
      0%,100% {{ opacity: 1; }}
      50%      {{ opacity: .4; }}
    }}

    /* ── Layout ── */
    .page {{ max-width: 1200px; margin: 0 auto; padding: 28px 32px; }}

    /* ── Stat cards ── */
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 24px;
    }}
    .stat-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px 24px;
      box-shadow: var(--shadow);
      display: flex;
      flex-direction: column;
      gap: 4px;
      border-top: 3px solid transparent;
      transition: box-shadow .15s;
    }}
    .stat-card:hover {{ box-shadow: var(--shadow-md); }}
    .stat-card.sev-card-critical {{ border-top-color: #dc2626; }}
    .stat-card.sev-card-high     {{ border-top-color: #ea580c; }}
    .stat-card.sev-card-medium   {{ border-top-color: #ca8a04; }}
    .stat-card.sev-card-low      {{ border-top-color: #16a34a; }}
    .stat-icon  {{ font-size: 20px; }}
    .stat-count {{ font-size: 32px; font-weight: 600; line-height: 1.1; color: var(--text); }}
    .stat-label {{ font-size: 12px; font-weight: 500; color: var(--muted); letter-spacing: .05em; text-transform: uppercase; }}

    /* ── Panel ── */
    .panel {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    .panel-header {{
      padding: 16px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      background: var(--surface);
    }}
    .panel-title {{
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      flex: 1;
    }}
    .record-count {{
      background: var(--accent-bg);
      color: var(--accent);
      font-size: 12px;
      font-weight: 600;
      padding: 2px 10px;
      border-radius: 99px;
    }}

    /* ── Filters ── */
    .filters {{
      padding: 12px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      background: var(--surface2);
    }}
    .filter-group {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .filter-group label {{
      font-size: 12px;
      font-weight: 500;
      color: var(--muted);
    }}
    select, input[type=search] {{
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
      padding: 5px 10px;
      font-size: 13px;
      font-family: var(--font);
      outline: none;
      transition: border-color .15s, box-shadow .15s;
    }}
    select:focus, input[type=search]:focus {{
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(37,99,235,.1);
    }}
    input[type=search] {{ min-width: 200px; }}

    /* ── Table ── */
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; }}
    thead th {{
      text-align: left;
      padding: 10px 16px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--muted);
      background: var(--surface2);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }}
    tbody tr {{
      border-bottom: 1px solid var(--border);
      transition: background .1s;
    }}
    tbody tr:last-child {{ border-bottom: none; }}
    tbody tr:hover {{ background: #f8f9ff; }}
    tbody tr.hidden {{ display: none; }}
    td {{ padding: 11px 16px; vertical-align: top; }}

    /* Severity indicator bar */
    .sev-indicator {{
      width: 4px;
      height: 36px;
      border-radius: 99px;
      margin-top: 2px;
    }}
    .sev-indicator.sev-critical {{ background: #dc2626; }}
    .sev-indicator.sev-high     {{ background: #ea580c; }}
    .sev-indicator.sev-medium   {{ background: #ca8a04; }}
    .sev-indicator.sev-low      {{ background: #16a34a; }}
    .sev-indicator.sev-unknown  {{ background: #9ca3af; }}

    td:first-child {{ width: 20px; padding-right: 4px; }}

    .advisory-link {{
      color: var(--accent);
      text-decoration: none;
      font-weight: 500;
      font-size: 13px;
      display: block;
      margin-bottom: 3px;
      transition: color .1s;
    }}
    .advisory-link:hover {{ color: #1d4ed8; text-decoration: underline; }}
    .summary {{ color: var(--muted); font-size: 12px; line-height: 1.5; }}

    /* ── Badges ── */
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 99px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: .03em;
      white-space: nowrap;
    }}
    .sev-critical {{ background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }}
    .sev-high     {{ background: #fff7ed; color: #ea580c; border: 1px solid #fed7aa; }}
    .sev-medium   {{ background: #fefce8; color: #a16207; border: 1px solid #fde68a; }}
    .sev-low      {{ background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }}
    .sev-unknown  {{ background: #f9fafb; color: #6b7280; border: 1px solid #e5e7eb; }}

    .src-badge {{
      display: inline-block;
      background: var(--surface2);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 11px;
      font-weight: 500;
      padding: 2px 8px;
      border-radius: 6px;
      white-space: nowrap;
    }}

    .dt {{
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
    }}

    /* ── Empty state ── */
    .empty {{
      text-align: center;
      padding: 48px 0;
      color: var(--muted);
    }}
    .empty-icon {{ font-size: 32px; margin-bottom: 8px; }}

    /* ── Footer ── */
    footer {{
      margin-top: 24px;
      padding: 0 4px;
      color: var(--muted);
      font-size: 12px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}
    footer a:hover {{ text-decoration: underline; }}

    @media (max-width: 768px) {{
      .page {{ padding: 16px; }}
      .stat-grid {{ grid-template-columns: repeat(2, 1fr); }}
      .topbar {{ padding: 0 16px; }}
    }}
  </style>
</head>
<body>

<div class="topbar">
  <div class="topbar-logo">
    🛡 <span>Security</span> Feed
  </div>
  <div class="topbar-meta">
    <span class="live-dot"></span>
    Aktualizováno {now} &nbsp;·&nbsp; okno 72 h
  </div>
</div>

<div class="page">

  <!-- Stat cards -->
  <div class="stat-grid">
    {cards}
  </div>

  <!-- Main panel -->
  <div class="panel">

    <div class="panel-header">
      <div class="panel-title">Bezpečnostní advisories</div>
      <span class="record-count" id="record-count">{total} záznamů</span>
    </div>

    <div class="filters">
      <div class="filter-group">
        <label>Závažnost</label>
        <select id="f-sev" onchange="applyFilters()">
          <option value="">Vše</option>
          <option value="critical">CRITICAL</option>
          <option value="high">HIGH</option>
          <option value="medium">MEDIUM</option>
          <option value="low">LOW</option>
        </select>
      </div>
      <div class="filter-group">
        <label>Zdroj</label>
        <select id="f-src" onchange="applyFilters()">
          <option value="">Vše</option>
          {src_opts}
        </select>
      </div>
      <div class="filter-group">
        <label>Hledat</label>
        <input type="search" id="f-search" placeholder="CVE-…, klíčové slovo" oninput="applyFilters()">
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th></th>
            <th>Advisory</th>
            <th>Závažnost</th>
            <th>Zdroj</th>
            <th>Publikováno</th>
          </tr>
        </thead>
        <tbody id="tbody">
          {rows}
        </tbody>
      </table>
      <div class="empty" id="empty-state" style="display:none">
        <div class="empty-icon">🔍</div>
        Žádné záznamy neodpovídají filtru.
      </div>
    </div>

  </div>

  <footer>
    <span>Zdroje: Microsoft MSRC · CISA KEV · NVD · Cisco · Red Hat · VMware</span>
    <a href="data.json">📥 data.json</a>
    <a href="https://github.com/Bublays/Security_feed">GitHub</a>
  </footer>

</div>

<script>
  function applyFilters() {{
    const sev    = document.getElementById('f-sev').value;
    const src    = document.getElementById('f-src').value;
    const search = document.getElementById('f-search').value.toLowerCase();
    const rows   = document.querySelectorAll('#tbody .advisory-row');
    let visible  = 0;

    rows.forEach(row => {{
      const matchSev    = !sev    || row.dataset.severity === sev;
      const matchSrc    = !src    || row.dataset.source   === src;
      const matchSearch = !search || row.textContent.toLowerCase().includes(search);
      const show        = matchSev && matchSrc && matchSearch;
      row.classList.toggle('hidden', !show);
      if (show) visible++;
    }});

    document.getElementById('record-count').textContent = visible + ' záznamů';
    document.getElementById('empty-state').style.display = visible === 0 ? 'block' : 'none';
  }}
</script>

</body>
</html>"""

def main():
    src = Path("output/advisories.json")
    if not src.exists():
        print("output/advisories.json nenalezen")
        return

    advisories = json.loads(src.read_text())
    docs = Path("docs")
    docs.mkdir(exist_ok=True)

    (docs / "data.json").write_text(
        json.dumps(advisories, ensure_ascii=False, indent=2)
    )

    html = generate(advisories)
    (docs / "index.html").write_text(html, encoding="utf-8")
    print(f"Vygenerováno docs/index.html ({len(advisories)} záznamů)")

if __name__ == "__main__":
    main()
