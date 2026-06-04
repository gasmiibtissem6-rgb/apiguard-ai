import json
import os
from datetime import datetime
from rich.console import Console

console = Console()

class Reporter:
    def __init__(self, target, vulnerabilities, analysis, endpoints):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.analysis = analysis
        self.endpoints = endpoints
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.filename = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_html(self):
        vuln_rows = ""
        for v in self.vulnerabilities:
            color = {"CRITIQUE": "#ff4444", "HAUT": "#ff8800", "MOYEN": "#ffcc00", "BAS": "#44bb44"}.get(v["severity"], "#aaa")
            vuln_rows += f"""
            <tr>
                <td><code>{v['endpoint']}</code></td>
                <td style="color:{color};font-weight:bold">{v['type']}</td>
                <td style="color:{color}">{v['severity']}</td>
                <td>{v['description']}</td>
                <td><code>{v.get('poc','N/A')}</code></td>
            </tr>"""

        chains_html = ""
        for chain in self.analysis.get("attack_chains", []):
            chains_html += f"<div class='chain'><h4>🔗 {chain['name']} <span class='badge'>{chain['severity']}</span></h4><ol>"
            for step in chain["steps"]:
                chains_html += f"<li>{step}</li>"
            chains_html += "</ol></div>"

        remeds_html = "".join(f"<li>✅ {r}</li>" for r in self.analysis.get("prioritized_remediations", []))

        score = self.analysis.get("global_risk_score", 0)
        risk = self.analysis.get("risk_level", "N/A")
        score_color = "#ff4444" if score >= 8 else "#ff8800" if score >= 6 else "#ffcc00" if score >= 3 else "#44bb44"

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>APIGuard AI — Rapport {self.target}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  .header {{ background: linear-gradient(135deg, #161b22, #21262d); border: 1px solid #30363d; border-radius: 12px; padding: 30px; margin-bottom: 20px; }}
  h1 {{ color: #58a6ff; margin: 0 0 8px 0; }}
  .score {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
  .badge {{ background: {score_color}; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 12px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #21262d; padding: 10px; text-align: left; color: #8b949e; }}
  td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 13px; }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #79c0ff; }}
  .chain {{ background: #0d1117; border-left: 3px solid #58a6ff; padding: 12px; margin: 8px 0; border-radius: 4px; }}
  h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 8px; }}
  h4 {{ margin: 0 0 8px 0; color: #e3b341; }}
  ul, ol {{ padding-left: 20px; }}
  li {{ margin: 6px 0; }}
  .summary {{ background: #1c2128; border: 1px solid #388bfd; border-radius: 8px; padding: 16px; color: #e6edf3; }}
  .meta {{ color: #8b949e; font-size: 13px; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ APIGuard AI — Rapport de Sécurité</h1>
  <p class="meta">Cible: <strong>{self.target}</strong> | Date: {self.timestamp}</p>
  <div>Score de risque global: <span class="score">{score}</span><span style="font-size:20px;color:#8b949e">/10</span>
  &nbsp;<span class="badge">{risk}</span></div>
</div>

<div class="card">
  <h2>📋 Résumé Exécutif</h2>
  <div class="summary">{self.analysis.get('executive_summary','N/A')}</div>
  <br>
  <table>
    <tr><th>Endpoints analysés</th><th>Vulnérabilités</th><th>Critiques</th><th>Hautes</th><th>Moyennes</th></tr>
    <tr>
      <td>{self.analysis.get('attack_surface',0)}</td>
      <td>{len(self.vulnerabilities)}</td>
      <td style="color:#ff4444">{sum(1 for v in self.vulnerabilities if v['severity']=='CRITIQUE')}</td>
      <td style="color:#ff8800">{sum(1 for v in self.vulnerabilities if v['severity']=='HAUT')}</td>
      <td style="color:#ffcc00">{sum(1 for v in self.vulnerabilities if v['severity']=='MOYEN')}</td>
    </tr>
  </table>
</div>

<div class="card">
  <h2>🔗 Chaînes d'Attaque Prédites</h2>
  {chains_html if chains_html else '<p style="color:#8b949e">Aucune chaîne détectée.</p>'}
</div>

<div class="card">
  <h2>🐛 Vulnérabilités Détectées</h2>
  <table>
    <tr><th>Endpoint</th><th>Type</th><th>Sévérité</th><th>Description</th><th>PoC</th></tr>
    {vuln_rows if vuln_rows else '<tr><td colspan="5" style="color:#8b949e;text-align:center">Aucune vulnérabilité trouvée</td></tr>'}
  </table>
</div>

<div class="card">
  <h2>✅ Remédiations Prioritaires</h2>
  <ul>{remeds_html if remeds_html else '<li style="color:#8b949e">Aucune action requise.</li>'}</ul>
</div>

<div class="card">
  <h2>🔍 Endpoints Découverts</h2>
  <table>
    <tr><th>URL</th><th>Status</th><th>Type</th></tr>
    {"".join(f'<tr><td><code>{e.get("url","")}</code></td><td>{e.get("status","")}</td><td>{e.get("content_type","")[:40]}</td></tr>' for e in self.endpoints)}
  </table>
</div>

<p class="meta" style="text-align:center;margin-top:30px">Généré par APIGuard AI | {self.timestamp}</p>
</body>
</html>"""

        path = f"output/report_{self.filename}.html"
        os.makedirs("output", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        console.print(f"[green][+] Rapport HTML: {path}[/green]")
        return path

    def generate_json(self):
        data = {
            "target": self.target,
            "timestamp": self.timestamp,
            "analysis": self.analysis,
            "vulnerabilities": self.vulnerabilities,
            "endpoints": self.endpoints
        }
        path = f"output/report_{self.filename}.json"
        os.makedirs("output", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        console.print(f"[green][+] Rapport JSON: {path}[/green]")
        return path

    def run(self):
        html_path = self.generate_html()
        json_path = self.generate_json()
        return html_path, json_path
