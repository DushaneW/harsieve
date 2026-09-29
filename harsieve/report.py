"""Self-contained report rendered only from the sanitized projection."""

from __future__ import annotations

import html
import math
from datetime import datetime
from importlib.resources import files


def summary(clean: dict) -> dict:
    entries = clean["log"]["entries"]
    durations = sorted(entry["time"] for entry in entries)
    p95 = durations[max(0, math.ceil(len(durations) * 0.95) - 1)] if durations else 0
    return {
        "requests": len(entries),
        "http_errors": sum(e["response"]["status"] >= 400 for e in entries),
        "no_response": sum(e["response"]["status"] == 0 for e in entries),
        "p95_ms": p95,
        "known_response_bytes": sum(max(0, e["response"]["bodySize"]) for e in entries),
        "unknown_response_sizes": sum(e["response"]["bodySize"] < 0 for e in entries),
    }


def render(clean: dict, audit: dict) -> str:
    """Internal renderer; accepts sanitize() output, never an original HAR."""
    entries = clean["log"]["entries"]
    stats = summary(clean)
    offsets = []
    base = datetime.fromisoformat("2000-01-01T00:00:00+00:00")
    for entry in entries:
        stamp = datetime.fromisoformat(entry["startedDateTime"].replace("Z", "+00:00"))
        offsets.append((stamp - base).total_seconds() * 1000)
    span = (
        max((offset + e["time"] for offset, e in zip(offsets, entries, strict=True)), default=1)
        or 1
    )

    rows = []
    for index, (entry, offset) in enumerate(zip(entries, offsets, strict=True), 1):
        request, response = entry["request"], entry["response"]
        url = html.escape(request["url"])
        status = response["status"]
        group = "error" if status >= 400 else "none" if status == 0 else "ok"
        left = max(0, min(100, offset / span * 100))
        width = max(0.2, min(100 - left, entry["time"] / span * 100))
        size = response["bodySize"]
        size_text = f"{size:,} B" if size >= 0 else "unknown"
        rows.append(
            f'<tr data-group="{group}" data-duration="{entry["time"]}">'
            f'<td class="index">{index:03d}</td>'
            f'<td><span class="method">{html.escape(request["method"])}</span>'
            f'<span class="endpoint">{url}</span></td>'
            f'<td><span class="status {group}">{status or "—"}</span></td>'
            f'<td class="number">{size_text}</td>'
            f'<td class="number">{entry["time"]:,.1f} ms</td>'
            f'<td><div class="track"><span class="bar {group}" '
            f'style="left:{left:.4f}%;width:{width:.4f}%"></span></div></td></tr>'
        )

    cards = [
        ("REQUESTS", str(stats["requests"]), "captured entries"),
        ("HTTP ERRORS", str(stats["http_errors"]), "status 400–599"),
        ("P95 DURATION", f"{stats['p95_ms']:,.1f} ms", "nearest-rank percentile"),
        (
            "RESPONSE DATA",
            f"{stats['known_response_bytes'] / 1024:,.1f} KiB",
            f"{stats['unknown_response_sizes']} unknown sizes",
        ),
    ]
    card_html = "".join(
        f'<article class="metric"><p>{title}</p><strong>{value}</strong><small>{note}</small></article>'
        for title, value, note in cards
    )
    policy = "".join(f"<li>{html.escape(line)}</li>" for line in audit["policy"])
    css = files("harsieve").joinpath("report.css").read_text(encoding="utf-8")
    js = files("harsieve").joinpath("report.js").read_text(encoding="utf-8")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>HARSieve · Capture overview</title><style>{css}</style></head><body>
<header>
  <a class="brand" href="#top"><span class="mark">H/</span><span>HARSieve</span></a>
</header>
<main id="top">
<section class="hero">
  <div class="hero-copy">
    <p class="eyebrow">CAPTURE ANALYSIS</p>
    <h1>Network activity,<br><span>without the private data.</span></h1>
    <p class="intro">A metadata-only projection of the capture. Timing, status codes and endpoint relationships remain useful for debugging while original addresses, headers and payloads are removed.</p>
  </div>
  <aside class="hero-note">
    <span class="check">✓</span>
    <strong>Metadata-only profile</strong>
    <dl>
      <div><dt>ORIGINS</dt><dd>{audit['origins_aliased']}</dd></div>
      <div><dt>PATHS</dt><dd>{audit['paths_aliased']}</dd></div>
      <div><dt>EXTERNAL RESOURCES</dt><dd>NONE</dd></div>
    </dl>
  </aside>
</section>
<section class="metrics" aria-label="Capture summary">{card_html}</section>
<section class="network">
  <div class="section-title">
    <div><p class="eyebrow">01 / REQUESTS</p><h2>Request waterfall</h2></div>
    <span class="capture-span">{span:,.1f} ms span</span>
  </div>
  <div class="toolbar">
    <label class="search-label">Filter endpoints <input id="search" type="search" placeholder="host-001, POST…" autocomplete="off"></label>
    <label>Status <select id="status"><option value="all">All requests</option><option value="error">HTTP errors</option><option value="none">No response</option></select></label>
    <label>Order <select id="sort"><option value="capture">Capture order</option><option value="slow">Slowest first</option></select></label>
    <span id="count" aria-live="polite">{len(entries)} requests</span>
  </div>
  <div class="table-wrap"><table><thead><tr><th>#</th><th>ENDPOINT ALIAS</th><th>STATUS</th><th>BODY SIZE</th><th>DURATION</th><th>RELATIVE TIMELINE</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>
  <p id="empty" {"hidden" if entries else ""}>No requests match this view.</p>
</section>
<section class="policy">
  <div><p class="eyebrow">02 / PRIVACY</p><h2>What survived the sieve</h2><ul>{policy}</ul></div>
  <aside><strong>Pseudonymized ≠ anonymous.</strong><p>Timing, sizes, status codes and traffic shape can reveal activity. Review before sharing. Header and body debugging requires the original capture, kept locally.</p><p>Status 0 means no recorded HTTP response. Unknown sizes are excluded from the byte total. SSL timing overlaps connect timing and is not added again.</p></aside>
</section>
<footer>HARSieve {html.escape(audit["tool_version"])} <span>Local processing · No telemetry</span></footer>
</main><script>{js}</script></body></html>"""
