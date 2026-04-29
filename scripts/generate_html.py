# scripts/generate_html.py
import json
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
SEVERITY_COLOR = {
    "CRITICAL": ("#7f1d1d", "#fca5a5"),
    "HIGH":     ("#7c2d12", "#fdba74"),
    "MEDIUM":   ("#713f12", "#fde68a"),
    "LOW":      ("#14532d", "#86efac"),
    "UNKNOWN":  ("#374151", "#d1d5db"),
}

SOURCE_LABEL = {
    "msrc":     "Microsoft MSRC",
    "cisa_kev": "CISA KEV",
    "nvd":      "NVD",
    "cisco":    "Cisco",
    "redhat":   "Red Hat",
    "vmware":   "VMware",
}

def badge(severity: str) -> str:
    bg, fg = SEVERITY_COLOR.get(severity, SEVERITY_COLOR["UNKNOWN"])
    # fg je světlá barva textu, bg tmavá pro tmavý badge
    return (
        f'<span class="badge sev-{severity.lower()}">'
        f'{severity}</span>'
    )

def source_badge(source: str) -> str:
    label = SOURCE_LABEL.get(source, source)
    return f'<span class="src-badge">{label}</span>'

def format_dt(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso

def render_row(item: dict) -> str:
    sev   = item.get("severity", "UNKNOWN")
    title = item.get("title", "")[:120]
    link  = item.get("link", "#")
    pub   = format_dt(item.get("published", ""))
    src   = item.get("source", "")
    summ  = item.get("summary", "")[:300]

    return f"""
      <tr class="advisory-row" data-severity="{sev.lower()}" data-source="{src}">
        <td>{badge(sev)}</td>
        <td>
          <a href="{link}" target="_blank" rel="noopener" class="advisory-link">{title}</a>
          <div class="summary">{summ}</div>
        </td>
        <td class="nowrap">{source_badge(src)}</td>
        <td class="nowrap dt">{pub}</td>
      </tr>"""

def render_stats(items: list[dict]) -> str:
    counts = {}
    for item in items:
        s = item.get("severity", "UNKNOWN")
        counts[s] = counts.get(s, 0) + 1
    parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        n = counts.get(sev, 0)
        if n:
            parts.append(f'<span class="stat-pill sev-{sev.lower()}">'
                         f'{sev} <strong>{n}</strong></span>')
    return " ".join(parts)

def generate(advisories: list[dict]) -> str:
    advisories.sort(
        key=lambda x: (SEVERITY_ORDER.get(x.get("severity","UNKNOWN"), 4),
                       x.get("published", "")),
        reverse=False
    )
    # secondary sort: nejnovější nahoře v rámci stejné závažnosti
    advisories.sort(
        key=lambda x: (SEVERITY_ORDER.get(x.get("severity","UNKNOWN"), 4),
                       x.get("published", "")),
    )

    rows = "".join(render_row(i) for i in advisories)
    stats = render_stats(advisories)
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = len(advisories)

    # Unikátní zdroje pro filtr
    sources = sorted({i.get("source","") for i in advisories})
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
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:      #0f1117;
      --bg2:     #1a1d27;
      --bg3:     #22263a;
      --border:  #2e3347;
      --text:    #e2e4ef;
      --muted:   #8b8fa8;
      --accent:  #4f72ff;
      --radius:  6px;
      --font:    'Inter', 'Segoe UI', system-ui, sans-serif;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }}

    /* ── Header ── */
    header {{
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      padding: 20px 32px;
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }}
    header h1 {{
      font-size: 18px;
      font-weight: 600;
      letter-spacing: .01em;
      color: #fff;
      flex: 1;
    }}
    .meta {{ color: var(--muted); font-size: 12px; }}

    /* ── Stats bar ── */
    .stats-bar {{
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      padding: 10px 32px;
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }}
    .stat-pill {{
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 99px;
      font-size: 12px;
      font-weight: 500;
    }}

    /* ── Filters ── */
    .filters {{
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      padding: 10px 32px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }}
    .filters label {{ color: var(--muted); font-size: 12px; }}
    .filters select, .filters input {{
      background: var(--bg3);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: var(--radius);
      padding: 5px 10px;
      font-size: 13px;
      outline: none;
    }}
    .filters select:focus, .filters input:focus {{
      border-color: var(--accent);
    }}
    .filter-count {{
      margin-left: auto;
      color: var(--muted);
      font-size: 12px;
    }}

    /* ── Table ── */
    .table-wrap {{
      padding: 24px 32px;
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    thead th {{
      text-align: left;
      padding: 8px 12px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--muted);
      border-bottom: 1px solid var(--border);
    }}
    tbody tr {{
      border-bottom: 1px solid var(--border);
      transition: background .1s;
    }}
    tbody tr:hover {{ background: var(--bg3); }}
    tbody tr.hidden {{ display: none; }}
    td {{ padding: 10px 12px; vertical-align: top; }}

    .advisory-link {{
      color: #93b4ff;
      text-decoration: none;
      font-weight: 500;
      font-size: 13px;
      display: block;
      margin-bottom: 3px;
    }}
    .advisory-link:hover {{ color: #c3d4ff; text-decoration: underline; }}
    .summary {{ color: var(--muted); font-size: 12px; line-height: 1.5; }}

    /* ── Badges ── */
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 99px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .04em;
      white-space: nowrap;
    }}
    .sev-critical {{ background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }}
    .sev-high     {{ background: #431407; color: #fdba74; border: 1px solid #7c2d12; }}
    .sev-medium   {{ background: #422006; color: #fde68a; border: 1px solid #713f12; }}
    .sev-low      {{ background: #052e16; color: #86efac; border: 1px solid #14532d; }}
    .sev-unknown  {{ background: #1f2937; color: #d1d5db; border: 1px solid #374151; }}

    /* stat pills use same colors */
    .stat-pill.sev-critical {{ background: #450a0a; color: #fca5a5; }}
    .stat-pill.sev-high     {{ background: #431407; color: #fdba74; }}
    .stat-pill.sev-medium   {{ background: #422006; color: #fde68a; }}
    .stat-pill.sev-low      {{ background: #052e16; color: #86efac; }}
    .stat-pill.sev-unknown  {{ background: #1f2937; color: #d1d5db; }}

    .src-badge {{
      display: inline-block;
      background: var(--bg3);
      border: 1px solid var(--border);
      color: var(--muted);
      font-size: 11px;
      padding: 2px 7px;
      border-radius: var(--radius);
      white-space: nowrap;
    }}

    .nowrap {{ white-space: nowrap; }}
    .dt {{ color: var(--muted); font-size: 12px; font-variant-numeric: tabular-nums; }}

    /* ── Empty state ── */
    .empty {{
      text-align: center;
      padding: 48px 0;
      color: var(--muted);
      font-size: 14px;
    }}

    /* ── Footer ── */
    footer {{
      padding: 16px 32px;
      border-top: 1px solid var(--border);
      color: var(--muted);
      font-size: 12px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }}
    footer a {{ color: #93b4ff; text-decoration: none; }}
  </style>
</head>
<body>

<header>
  <div>
    <h1>🛡 Security Advisory Feed</h1>
    <div class="meta">Automaticky generováno · {now} · okno 72 h · {total} záznamů</div>
  </div>
</header>

<div class="stats-bar">
  {stats}
</div>

<div class="filters">
  <label>Závažnost</label>
  <select id="f-sev" onchange="applyFilters()">
    <option value="">Vše</option>
    <option value="critical">CRITICAL</option>
    <option value="high">HIGH</option>
    <option value="medium">MEDIUM</option>
    <option value="low">LOW</option>
  </select>

  <label>Zdroj</label>
  <select id="f-src" onchange="applyFilters()">
    <option value="">Vše</option>
    {src_opts}
  </select>

  <label>Hledat</label>
  <input type="search" id="f-search" placeholder="CVE-…, klíčové slovo" oninput="applyFilters()">

  <span class="filter-count" id="filter-count">{total} záznamů</span>
</div>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th style="width:96px">Závažnost</th>
        <th>Advisory</th>
        <th style="width:120px">Zdroj</th>
        <th style="width:160px">Publikováno</th>
      </tr>
    </thead>
    <tbody id="tbody">
      {rows}
    </tbody>
  </table>
  <div class="empty" id="empty-state" style="display:none">Žádné záznamy neodpovídají filtru.</div>
</div>

<footer>
  <span>Zdroje: Microsoft MSRC · CISA KEV · NVD · Cisco · Red Hat · VMware</span>
  <span>·</span>
  <a href="data.json">📥 data.json</a>
  <span>·</span>
  <a href="https://github.com/{'{'}your-org{'}'}/{'{'}your-repo{'}'}">GitHub</a>
</footer>

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

    document.getElementById('filter-count').textContent = visible + ' záznamů';
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

    # Zkopíruje data.json pro případné další použití
    (docs / "data.json").write_text(
        json.dumps(advisories, ensure_ascii=False, indent=2)
    )

    html = generate(advisories)
    (docs / "index.html").write_text(html, encoding="utf-8")
    print(f"Vygenerováno docs/index.html ({len(advisories)} záznamů)")

if __name__ == "__main__":
    main()
