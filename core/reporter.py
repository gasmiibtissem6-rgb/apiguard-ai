from datetime import datetime
import json
import os
from rich.console import Console

console = Console()

class Reporter:
    def __init__(self, target, vulnerabilities, analysis, endpoints, attack_chains=None):
        self.target = target
        self.vulnerabilities = vulnerabilities
        self.analysis = analysis
        self.endpoints = endpoints
        self.attack_chains = attack_chains or {"chains": []}

    def run(self):
        os.makedirs('output', exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = f"output/report_{timestamp}.html"
        json_path = f"output/report_{timestamp}.json"

        # Générer HTML
        self._generate_html(html_path)

        # Générer JSON
        with open(json_path, 'w') as f:
            json.dump({
                "target": self.target,
                "timestamp": timestamp,
                "vulnerabilities": self.vulnerabilities,
                "analysis": self.analysis,
                "attack_chains": self.attack_chains,
                "endpoints": [e.get('url','') for e in self.endpoints]
            }, f, indent=2, ensure_ascii=False)

        console.print(f"[green][+] Rapport HTML: {html_path}[/green]")
        console.print(f"[green][+] Rapport JSON: {json_path}[/green]")
        return html_path, json_path

    def _generate_html(self, path):
        score = self.analysis.get("global_risk_score", 0)
        risk = self.analysis.get("risk_level", "N/A")
        summary = self.analysis.get("executive_summary", "")
        chains = self.attack_chains.get("chains", [])

        score_color = "#ff4757" if score >= 8 else "#ffa502" if score >= 5 else "#2ed573"

        critiques = sum(1 for v in self.vulnerabilities if v.get('severity') == 'CRITIQUE')
        hautes = sum(1 for v in self.vulnerabilities if v.get('severity') == 'HAUT')
        moyennes = sum(1 for v in self.vulnerabilities if v.get('severity') == 'MOYEN')

        # Vulnérabilités HTML
        vuln_rows = ""
        for v in self.vulnerabilities:
            sev = v.get('severity', '')
            sev_color = "#ff4757" if sev == "CRITIQUE" else "#ff6b81" if sev == "HAUT" else "#ffa502"
            vuln_rows += f"""
            <tr>
                <td><code>{v.get('endpoint','')}</code></td>
                <td style="color:{sev_color};font-weight:bold">{v.get('type','')}</td>
                <td style="color:{sev_color};font-weight:bold">{sev}</td>
                <td>{v.get('description','')[:150]}</td>
                <td><code style="font-size:0.75em">{v.get('poc','')[:200]}</code></td>
            </tr>"""

        # Attack Chains HTML
        chains_html = ""
        for chain in chains:
            sev = chain.get('severity', 'MOYEN')
            c = "#ff4757" if sev == "CRITIQUE" else "#ffa502"
            steps_html = ""
            for step in chain.get('steps', []):
                steps_html += f"""
                <div class="step">
                    <span class="step-num">Étape {step.get('step','')}</span>
                    <span class="step-action">{step.get('action','')}</span>
                    <span class="step-vuln">via {step.get('vulnerability_used','')}</span>
                    <span class="step-result">→ {step.get('result','')}</span>
                </div>"""

            mitigations = "".join(f"<li>{m}</li>" for m in chain.get('mitigations', []))

            chains_html += f"""
            <div class="chain-card" style="border-left:4px solid {c}">
                <div class="chain-header">
                    <span class="chain-name">⛓️ {chain.get('name','')}</span>
                    <span class="chain-badge" style="background:{c}">{sev}</span>
                    <span class="chain-prob">{chain.get('probability',0)}% probabilité</span>
                </div>
                <div class="chain-steps">{steps_html}</div>
                <div class="chain-impact">
                    <strong>Impact final:</strong> {chain.get('final_impact','')}
                </div>
                <div class="chain-mitigations">
                    <strong>Mitigations:</strong><ul>{mitigations}</ul>
                </div>
            </div>"""

        # Endpoints HTML
        ep_rows = ""
        for ep in self.endpoints[:50]:
            status = ep.get('status', '')
            color = "#2ed573" if status == 200 else "#ffa502" if status in [401,403] else "#747d8c"
            ep_rows += f"""
            <tr>
                <td><a href="{ep.get('url','')}" style="color:#74b9ff">{ep.get('url','')}</a></td>
                <td style="color:{color}">{status}</td>
                <td>{ep.get('content_type','')[:30]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>APIGuard AI v3.0 — {self.target}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Segoe UI',sans-serif; background:#0d1117; color:#e6edf3; }}
.header {{ background:linear-gradient(135deg,#161b22,#0d1117);
           padding:40px; border-bottom:3px solid #ff4757; }}
.header h1 {{ font-size:2.2em; color:#ff4757; letter-spacing:2px; }}
.header p {{ color:#8b949e; margin-top:8px; }}
.badge {{ background:#21262d; padding:6px 14px; border-radius:20px;
          font-size:0.85em; margin:4px; display:inline-block; }}
.container {{ max-width:1400px; margin:0 auto; padding:30px; }}
.score-box {{ background:#161b22; border:2px solid {score_color};
              border-radius:12px; padding:30px; text-align:center; margin:20px 0; }}
.score-num {{ font-size:4em; font-weight:bold; color:{score_color}; }}
.score-label {{ font-size:1.2em; color:{score_color}; letter-spacing:4px; }}
.stats {{ display:grid; grid-template-columns:repeat(5,1fr); gap:15px; margin:20px 0; }}
.stat {{ background:#161b22; border-radius:10px; padding:20px; text-align:center;
         border-top:3px solid #58a6ff; }}
.stat-num {{ font-size:2.2em; font-weight:bold; color:#58a6ff; }}
.stat-label {{ color:#8b949e; font-size:0.85em; margin-top:5px; }}
.section {{ background:#161b22; border-radius:10px; padding:25px; margin:20px 0; }}
.section h2 {{ color:#58a6ff; margin-bottom:15px; font-size:1.2em;
               border-bottom:1px solid #21262d; padding-bottom:10px; }}
table {{ width:100%; border-collapse:collapse; }}
th {{ background:#21262d; padding:12px; text-align:left; color:#8b949e; font-size:0.85em; }}
td {{ padding:10px 12px; border-bottom:1px solid #21262d; font-size:0.88em; }}
code {{ background:#21262d; padding:2px 6px; border-radius:4px;
        font-family:monospace; font-size:0.82em; color:#79c0ff; }}
.chain-card {{ background:#21262d; border-radius:8px; padding:20px; margin:15px 0; }}
.chain-header {{ display:flex; align-items:center; gap:15px; margin-bottom:15px; }}
.chain-name {{ font-size:1.1em; font-weight:bold; color:#e6edf3; }}
.chain-badge {{ padding:4px 12px; border-radius:20px; font-size:0.8em;
                font-weight:bold; color:white; }}
.chain-prob {{ color:#8b949e; font-size:0.85em; }}
.step {{ display:flex; gap:10px; align-items:flex-start; padding:8px 0;
         border-bottom:1px solid #30363d; }}
.step-num {{ background:#58a6ff; color:#0d1117; padding:2px 8px; border-radius:10px;
             font-size:0.78em; font-weight:bold; white-space:nowrap; }}
.step-action {{ color:#e6edf3; font-weight:bold; min-width:200px; }}
.step-vuln {{ color:#f0883e; font-size:0.85em; }}
.step-result {{ color:#3fb950; font-size:0.85em; }}
.chain-impact {{ margin-top:12px; color:#ff4757; padding:10px;
                 background:rgba(255,71,87,0.1); border-radius:6px; }}
.chain-mitigations {{ margin-top:10px; color:#3fb950; }}
.chain-mitigations ul {{ margin-left:20px; }}
.exec-summary {{ background:rgba(88,166,255,0.1); border:1px solid #58a6ff;
                 border-radius:8px; padding:20px; color:#cdd9e5; line-height:1.8; }}
.footer {{ text-align:center; padding:30px; color:#8b949e;
           border-top:1px solid #21262d; margin-top:40px; }}
</style>
</head>
<body>
<div class="header">
    <h1>🛡️ APIGuard AI v3.0</h1>
    <p>AI-Powered API Security Scanner — OWASP API Top 10 + Attack Chain Predictor</p>
    <div style="margin-top:15px">
        <span class="badge">🎯 {self.target}</span>
        <span class="badge">📅 {datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
        <span class="badge">🤖 Ollama/llama3</span>
    </div>
</div>

<div class="container">
    <div class="score-box">
        <div class="score-num">{score}/10</div>
        <div class="score-label">SCORE DE RISQUE GLOBAL — {risk}</div>
    </div>

    <div class="stats">
        <div class="stat">
            <div class="stat-num" style="color:#58a6ff">{len(self.endpoints)}</div>
            <div class="stat-label">🔍 Endpoints</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#ff4757">{critiques}</div>
            <div class="stat-label">🔴 Critiques</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#ff6b81">{hautes}</div>
            <div class="stat-label">🟠 Hautes</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#ffa502">{moyennes}</div>
            <div class="stat-label">🟡 Moyennes</div>
        </div>
        <div class="stat">
            <div class="stat-num" style="color:#ff4757">{len(chains)}</div>
            <div class="stat-label">⛓️ Chaînes IA</div>
        </div>
    </div>

    <div class="section">
        <h2>📋 Résumé Exécutif</h2>
        <div class="exec-summary">{summary}</div>
    </div>

    <div class="section">
        <h2>🧠 AI Attack Chain Predictor</h2>
        <p style="color:#8b949e;margin-bottom:15px">
            L'IA a analysé les vulnérabilités et prédit les chaînes d'exploitation possibles :
        </p>
        {chains_html if chains_html else '<p style="color:#8b949e">Aucune chaîne détectée</p>'}
    </div>

    <div class="section">
        <h2>🐛 Vulnérabilités Détectées ({len(self.vulnerabilities)})</h2>
        <table>
            <tr>
                <th>Endpoint</th><th>Type</th><th>Sévérité</th>
                <th>Description</th><th>PoC</th>
            </tr>
            {vuln_rows}
        </table>
    </div>

    <div class="section">
        <h2>🔍 Endpoints Découverts ({len(self.endpoints)})</h2>
        <table>
            <tr><th>URL</th><th>Status</th><th>Type</th></tr>
            {ep_rows}
        </table>
    </div>
</div>

<div class="footer">
    <p>APIGuard AI v3.0 — Généré par IA (Ollama/llama3) ⚠️ Usage autorisé uniquement</p>
</div>
</body>
</html>"""

        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
