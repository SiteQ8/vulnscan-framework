"""
Report Generator
Produces professional pentest reports in HTML, JSON, and PDF formats.
"""

import json
import os
import hashlib
from datetime import datetime
from utils.logger import get_logger


SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#65a30d",
    "info":     "#0284c7",
}

SEVERITY_BG = {
    "critical": "#fef2f2",
    "high":     "#fff7ed",
    "medium":   "#fffbeb",
    "low":      "#f7fee7",
    "info":     "#f0f9ff",
}


class ReportGenerator:
    def __init__(self, results: dict, output_dir: str = "reports"):
        self.results = results
        self.output_dir = output_dir
        self.logger = get_logger()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.target_slug = results.get("target", "target").replace("https://", "").replace("http://", "").replace("/", "_")[:40]

    def generate(self, fmt: str = "html") -> str:
        os.makedirs(self.output_dir, exist_ok=True)
        if fmt == "html":
            return self._generate_html()
        elif fmt == "json":
            return self._generate_json()
        elif fmt == "pdf":
            return self._generate_pdf()
        else:
            raise ValueError(f"Unknown format: {fmt}")

    # ── HTML Report ────────────────────────────────────────────────────────────

    def _generate_html(self) -> str:
        path = os.path.join(self.output_dir, f"report_{self.target_slug}_{self.timestamp}.html")
        r = self.results
        vulns = r.get("vulnerabilities", [])
        preds = r.get("ml_predictions", [])
        ports = r.get("ports", {})
        recon = r.get("recon", {})
        risk_score = r.get("risk_score", 0)

        severity_counts = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
        for v in vulns:
            s = v.get("severity", "info").lower()
            severity_counts[s] = severity_counts.get(s, 0) + 1

        open_ports = {p: d for p, d in ports.items() if isinstance(d, dict) and d.get("state") == "open"}

        vuln_rows = ""
        for i, v in enumerate(vulns):
            sev = v.get("severity", "info").lower()
            color = SEVERITY_COLORS.get(sev, "#64748b")
            bg = SEVERITY_BG.get(sev, "#f8fafc")
            vuln_rows += f"""
            <tr style="background:{bg}">
                <td><span class="badge" style="background:{color};color:white">{sev.upper()}</span></td>
                <td><strong>{v.get('type','')}</strong></td>
                <td><code>{v.get('url','')[:80]}</code></td>
                <td><code>{v.get('parameter','')}</code></td>
                <td><small>{v.get('description','')[:120]}</small></td>
                <td><small style="color:#166534">{v.get('remediation','')[:100]}</small></td>
            </tr>"""

        port_rows = ""
        for port, data in sorted(open_ports.items(), key=lambda x: int(x[0])):
            vuln_note = data.get("vulnerability", {}).get("issue", "")
            vuln_html = f'<br><span style="color:#dc2626;font-size:11px">⚠ {vuln_note}</span>' if vuln_note else ""
            port_rows += f"""
            <tr>
                <td><strong>{port}</strong></td>
                <td>{data.get('protocol','tcp').upper()}</td>
                <td>{data.get('service','')}</td>
                <td><code style="font-size:11px">{data.get('version','') or data.get('banner','')[:60]}</code>{vuln_html}</td>
            </tr>"""

        pred_cards = ""
        for pred in preds[:10]:
            sev = pred.get("severity", "medium").lower()
            color = SEVERITY_COLORS.get(sev, "#64748b")
            cves = ", ".join(pred.get("cve_refs", [])) or "N/A"
            vulns_list = "".join(f"<li>{v}</li>" for v in pred.get("predicted_vulns", []))
            pred_cards += f"""
            <div class="pred-card" style="border-left:4px solid {color}">
                <div class="pred-header">
                    <span class="badge" style="background:{color};color:white">{sev.upper()}</span>
                    <strong>{pred.get('name','')}</strong>
                    <span class="confidence">Confidence: {pred.get('confidence_pct','')}</span>
                </div>
                <ul>{vulns_list}</ul>
                <div class="cve-refs">CVE References: {cves}</div>
                <div style="font-size:11px;color:#6b7280">Source: {pred.get('source','')}</div>
            </div>"""

        techs = recon.get("technologies", [])
        tech_badges = "".join(f'<span class="tech-badge">{t}</span>' for t in techs)

        subdomains = recon.get("subdomains", [])
        sub_rows = "".join(f"<tr><td>{s.get('subdomain','')}</td><td>{s.get('ip','')}</td></tr>" for s in subdomains)

        exposed_paths = recon.get("open_paths", [])
        def _mk_path_row(p):
            sev = p.get("severity", "low")
            c = SEVERITY_COLORS.get(sev, "#64748b")
            return ("<tr><td><code>" + p.get("path","") + "</code></td>"
                    "<td><span class='badge' style='background:" + c + ";color:white'>"
                    + sev.upper() + "</span></td>"
                    "<td>" + str(p.get("status","")) + "</td></tr>")
        path_rows = "".join(_mk_path_row(p) for p in exposed_paths)

        risk_color = "#dc2626" if risk_score >= 70 else ("#d97706" if risk_score >= 40 else "#16a34a")
        risk_label = "CRITICAL" if risk_score >= 70 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 30 else "LOW"))

        waf = recon.get("waf", {})
        ssl = recon.get("ssl_cert", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VulnScan Report — {r.get('target','')}</title>
<style>
  :root {{
    --primary: #1e293b;
    --accent: #3b82f6;
    --danger: #dc2626;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f1f5f9; color: #1e293b; }}
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); color: white; padding: 40px 60px; }}
  .header h1 {{ font-size: 2rem; letter-spacing: -0.5px; }}
  .header .meta {{ margin-top: 8px; opacity: 0.7; font-size: 14px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 30px 20px; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card h2 {{ font-size: 1.1rem; color: #475569; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }}
  .card h3 {{ font-size: 1rem; margin-bottom: 12px; }}
  .risk-score {{ font-size: 4rem; font-weight: 800; color: {risk_color}; line-height: 1; }}
  .risk-label {{ font-size: 1.2rem; color: {risk_color}; font-weight: 600; margin-top: 4px; }}
  .stat {{ text-align: center; padding: 16px; }}
  .stat .num {{ font-size: 2.5rem; font-weight: 800; }}
  .stat .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #64748b; margin-top: 4px; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #f8fafc; padding: 10px 12px; text-align: left; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; border-bottom: 1px solid #e2e8f0; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  tr:hover td {{ background: #f8fafc; }}
  code {{ background: #f1f5f9; padding: 1px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; word-break: break-all; }}
  .tech-badge {{ display: inline-block; background: #dbeafe; color: #1d4ed8; padding: 3px 10px; border-radius: 9999px; font-size: 12px; margin: 2px; }}
  .pred-card {{ background: white; border-radius: 10px; padding: 16px; margin-bottom: 12px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }}
  .pred-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }}
  .confidence {{ margin-left: auto; font-size: 13px; font-weight: 700; color: #3b82f6; }}
  .pred-card ul {{ padding-left: 20px; font-size: 13px; color: #475569; margin: 8px 0; }}
  .cve-refs {{ font-size: 11px; color: #6b7280; }}
  .section {{ margin-bottom: 28px; }}
  .section-title {{ font-size: 1.2rem; font-weight: 700; color: #0f172a; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }}
  .ssl-item {{ display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #f1f5f9; font-size: 13px; }}
  .footer {{ text-align: center; padding: 30px; color: #94a3b8; font-size: 12px; }}
  @media (max-width: 768px) {{ .grid-3,.grid-2 {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>🔍 VulnScan Security Report</h1>
  <div class="meta">
    <strong>Target:</strong> {r.get('target','')} &nbsp;|&nbsp;
    <strong>Mode:</strong> {r.get('mode','')} &nbsp;|&nbsp;
    <strong>Started:</strong> {r.get('scan_start','')} &nbsp;|&nbsp;
    <strong>Finished:</strong> {r.get('scan_end','')}
  </div>
</div>

<div class="container">

  <!-- Risk Overview -->
  <div class="section">
    <div class="grid-3">
      <div class="card" style="grid-column: span 1;">
        <h2>Overall Risk Score</h2>
        <div class="risk-score">{risk_score}</div>
        <div class="risk-label">{risk_label} RISK</div>
        <div style="margin-top:12px;font-size:12px;color:#64748b">Score out of 100 based on findings severity and count</div>
      </div>
      <div class="card">
        <h2>Vulnerabilities Found</h2>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
          <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['critical']}">{severity_counts['critical']}</div><div class="label">Critical</div></div>
          <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['high']}">{severity_counts['high']}</div><div class="label">High</div></div>
          <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['medium']}">{severity_counts['medium']}</div><div class="label">Medium</div></div>
          <div class="stat"><div class="num" style="color:{SEVERITY_COLORS['low']}">{severity_counts['low']}</div><div class="label">Low</div></div>
        </div>
      </div>
      <div class="card">
        <h2>Scan Coverage</h2>
        <div class="ssl-item"><span>Open Ports</span><strong>{len(open_ports)}</strong></div>
        <div class="ssl-item"><span>Technologies Found</span><strong>{len(techs)}</strong></div>
        <div class="ssl-item"><span>Subdomains</span><strong>{len(subdomains)}</strong></div>
        <div class="ssl-item"><span>Exposed Paths</span><strong>{len(exposed_paths)}</strong></div>
        <div class="ssl-item"><span>ML Predictions</span><strong>{len(preds)}</strong></div>
        <div class="ssl-item"><span>WAF Detected</span><strong>{"✅ " + waf.get('name','Yes') if waf.get('detected') else "❌ No"}</strong></div>
      </div>
    </div>
  </div>

  <!-- Technologies -->
  {"<div class='section'><div class='section-title'>🛠 Detected Technologies</div><div class='card'>" + tech_badges + "</div></div>" if techs else ""}

  <!-- SSL -->
  {"<div class='section'><div class='section-title'>🔒 SSL/TLS Certificate</div><div class='card'><div class='ssl-item'><span>Valid</span><strong>" + ("✅ Yes" if ssl.get("valid") else "❌ No") + "</strong></div><div class='ssl-item'><span>Issuer</span><strong>" + str(ssl.get("issuer",{}).get("organizationName","Unknown")) + "</strong></div><div class='ssl-item'><span>Days Remaining</span><strong>" + str(ssl.get("days_remaining","?")) + " days</strong></div><div class='ssl-item'><span>SANs</span><strong>" + str(len(ssl.get("alt_names",[]))) + "</strong></div></div></div>" if ssl else ""}

  <!-- Vulnerabilities Table -->
  <div class="section">
    <div class="section-title">🐛 Detected Vulnerabilities ({len(vulns)})</div>
    <div class="card" style="padding:0;overflow-x:auto">
      <table>
        <thead><tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Description</th><th>Remediation</th></tr></thead>
        <tbody>{vuln_rows if vuln_rows else "<tr><td colspan='6' style='text-align:center;padding:20px;color:#94a3b8'>No vulnerabilities detected</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- ML Predictions -->
  {"<div class='section'><div class='section-title'>🤖 ML Vulnerability Predictions (" + str(len(preds)) + ")</div>" + pred_cards + "</div>" if preds else ""}

  <!-- Open Ports -->
  {"<div class='section'><div class='section-title'>🔌 Open Ports (" + str(len(open_ports)) + ")</div><div class='card' style='padding:0;overflow-x:auto'><table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Banner / Notes</th></tr></thead><tbody>" + port_rows + "</tbody></table></div></div>" if port_rows else ""}

  <!-- Subdomains -->
  {"<div class='section'><div class='section-title'>🌐 Discovered Subdomains (" + str(len(subdomains)) + ")</div><div class='card' style='padding:0;overflow-x:auto'><table><thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead><tbody>" + sub_rows + "</tbody></table></div></div>" if sub_rows else ""}

  <!-- Exposed Paths -->
  {"<div class='section'><div class='section-title'>📂 Exposed Sensitive Paths (" + str(len(exposed_paths)) + ")</div><div class='card' style='padding:0;overflow-x:auto'><table><thead><tr><th>Path</th><th>Severity</th><th>HTTP Status</th></tr></thead><tbody>" + path_rows + "</tbody></table></div></div>" if path_rows else ""}

</div>
<div class="footer">
  Generated by <strong>VulnScan Framework</strong> — {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} —
  <a href="https://github.com/your-org/vulnscan-framework" style="color:#3b82f6">github.com/your-org/vulnscan-framework</a>
  <br><em>For authorized security testing only.</em>
</div>
</body></html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    # ── JSON Report ────────────────────────────────────────────────────────────

    def _generate_json(self) -> str:
        path = os.path.join(self.output_dir, f"report_{self.target_slug}_{self.timestamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2, default=str)
        return path

    # ── PDF Report (via reportlab) ─────────────────────────────────────────────

    def _generate_pdf(self) -> str:
        path = os.path.join(self.output_dir, f"report_{self.target_slug}_{self.timestamp}.pdf")
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.units import cm

            doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=2*cm, leftMargin=2*cm,
                                    topMargin=2*cm, bottomMargin=2*cm)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle("title", parent=styles["Heading1"], fontSize=20,
                                         textColor=colors.HexColor("#0f172a"), spaceAfter=6)
            subtitle_style = ParagraphStyle("sub", parent=styles["Normal"], fontSize=10,
                                            textColor=colors.HexColor("#64748b"), spaceAfter=20)
            h2_style = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13,
                                      textColor=colors.HexColor("#1e293b"), spaceAfter=8)
            body_style = ParagraphStyle("body", parent=styles["Normal"], fontSize=9, spaceAfter=4)

            r = self.results
            vulns = r.get("vulnerabilities", [])
            risk_score = r.get("risk_score", 0)

            story.append(Paragraph("VulnScan Security Assessment Report", title_style))
            story.append(Paragraph(
                f"Target: {r.get('target','')} | Mode: {r.get('mode','')} | Risk Score: {risk_score}/100",
                subtitle_style
            ))
            story.append(Spacer(1, 0.3*cm))

            # Summary table
            story.append(Paragraph("Executive Summary", h2_style))
            sev_counts = {s: sum(1 for v in vulns if v.get("severity","").lower() == s)
                          for s in ["critical", "high", "medium", "low"]}
            summary_data = [
                ["Metric", "Value"],
                ["Target", r.get("target", "")],
                ["Scan Mode", r.get("mode", "")],
                ["Risk Score", f"{risk_score}/100"],
                ["Critical Findings", str(sev_counts["critical"])],
                ["High Findings", str(sev_counts["high"])],
                ["Medium Findings", str(sev_counts["medium"])],
                ["Low Findings", str(sev_counts["low"])],
                ["ML Predictions", str(len(r.get("ml_predictions", [])))],
            ]
            t = Table(summary_data, colWidths=[6*cm, 11*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.5*cm))

            # Vulnerabilities table
            if vulns:
                story.append(Paragraph(f"Vulnerabilities ({len(vulns)})", h2_style))
                vuln_data = [["Severity", "Type", "URL", "Parameter"]]
                for v in vulns:
                    vuln_data.append([
                        v.get("severity", "").upper(),
                        v.get("type", "")[:40],
                        v.get("url", "")[:50],
                        v.get("parameter", "")[:20],
                    ])
                vt = Table(vuln_data, colWidths=[2.5*cm, 5*cm, 6*cm, 3.5*cm])
                vt.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]))
                story.append(vt)

            story.append(Spacer(1, 0.5*cm))
            story.append(Paragraph(
                "<i>Generated by VulnScan Framework — For authorized testing only.</i>",
                ParagraphStyle("footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey)
            ))

            doc.build(story)

        except ImportError:
            # Fallback: write basic text file with .pdf extension note
            with open(path.replace(".pdf", "_note.txt"), "w") as f:
                f.write("Install reportlab for PDF output: pip install reportlab\n")
                f.write(json.dumps(self.results, indent=2, default=str))
            path = path.replace(".pdf", "_note.txt")

        return path
