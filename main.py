import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

sys.path.insert(0, os.path.dirname(__file__))

from core.discovery import APIDiscovery
from core.scanner import VulnerabilityScanner
from core.reporter import Reporter
from core.business_logic import BusinessLogicTester
from ai.analyzer import AIAnalyzer
from ai.attack_chain import AttackChainPredictor

try:
    from core.crapi_scanner import CRAPIScanner
    CRAPI_AVAILABLE = True
except:
    CRAPI_AVAILABLE = False

console = Console()

BANNER = """
╔══════════════════════════════════════════════════╗
║         🛡️  APIGuard AI v4.0                     ║
║   Professional API Security Scanner              ║
║   OWASP API Top 10 + Business Logic + AI Chain   ║
╚══════════════════════════════════════════════════╝
"""

def main():
    console.print(Panel(Text(BANNER, style="bold cyan"), border_style="red"))

    if len(sys.argv) < 2:
        console.print("[yellow]Usage: python3 main.py <URL> [token JWT][/yellow]")
        sys.exit(1)

    target = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None

    if token:
        console.print(f"[green][*] Mode authentifié — token JWT fourni[/green]")
    console.print(f"[bold green][*] Cible: {target}[/bold green]\n")

    # ═══ Étape 1 — Discovery ═══
    console.print(Panel("[bold]Étape 1/5 — Découverte des endpoints[/bold]", style="blue"))
    discovery = APIDiscovery(target)
    endpoints = discovery.run()
    if not endpoints:
        console.print("[red][-] Aucun endpoint découvert.[/red]")
        sys.exit(1)

    # ═══ Étape 2 — OWASP Scanner ═══
    console.print(Panel("[bold]Étape 2/5 — Scan OWASP API Top 10[/bold]", style="yellow"))
    scanner = VulnerabilityScanner(target, auth_token=token)
    vulnerabilities = scanner.run(endpoints)

    # ═══ Étape 2b — crAPI Scanner ═══
    if token and CRAPI_AVAILABLE:
        console.print(Panel("[bold]Scan spécialisé crAPI...[/bold]", style="cyan"))
        crapi = CRAPIScanner(target, token)
        extra_vulns = crapi.run()
        vulnerabilities.extend(extra_vulns)

    # ═══ Étape 3 — Business Logic ═══
    console.print(Panel("[bold]Étape 3/5 — 🧩 Business Logic Tester[/bold]", style="green"))
    bl_tester = BusinessLogicTester(target, token)
    bl_vulns = bl_tester.run()
    vulnerabilities.extend(bl_vulns)

    # ═══ Étape 4 — AI Analysis ═══
    console.print(Panel("[bold]Étape 4/5 — 🤖 Analyse IA[/bold]", style="magenta"))
    analyzer = AIAnalyzer(target)
    analysis = analyzer.analyze(vulnerabilities, endpoints)

    # ═══ Étape 5 — Attack Chain ═══
    console.print(Panel("[bold]Étape 5/5 — 🧠 AI Attack Chain Predictor[/bold]", style="red"))
    predictor = AttackChainPredictor()
    attack_chains = predictor.predict(vulnerabilities, target)

    # Afficher chaînes
    chains = attack_chains.get("chains", [])
    if chains:
        console.print(f"\n[red bold][!] {len(chains)} chaînes d'attaque prédites :[/red bold]")
        for chain in chains:
            color = "red" if chain.get("severity") == "CRITIQUE" else "yellow"
            console.print(f"[{color}]  ⛓️  {chain['name']} — {chain['severity']} ({chain.get('probability',0)}%)[/{color}]")
            for step in chain.get("steps", []):
                console.print(f"[white]      Étape {step['step']}: {step['action']}[/white]")
            console.print(f"[{color}]      💥 Impact: {chain['final_impact']}[/{color}]\n")

    # Afficher Business Logic résultats
    if bl_vulns:
        console.print(f"\n[cyan bold][!] {len(bl_vulns)} vulnérabilités Business Logic :[/cyan bold]")
        for v in bl_vulns:
            color = "red" if v['severity'] == 'CRITIQUE' else "yellow"
            console.print(f"[{color}]  🧩 {v['severity']} — {v['type']} sur {v['endpoint']}[/{color}]")
            console.print(f"[white]      💰 Impact: {v.get('business_impact','N/A')}[/white]")

    # Rapport
    reporter = Reporter(target, vulnerabilities, analysis, endpoints, attack_chains)
    html_path, json_path = reporter.run()

    # Stats finales
    score = analysis.get("global_risk_score", 0)
    risk = analysis.get("risk_level", "N/A")
    score_color = "red" if score >= 8 else "yellow" if score >= 5 else "green"
    critiques = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITIQUE')
    hautes = sum(1 for v in vulnerabilities if v.get('severity') == 'HAUT')
    bl_count = len(bl_vulns)

    console.print(f"""
[red]╔══════════════════════════════════════════╗
║       SCAN TERMINÉ v4.0 — COMPLET        ║
╠══════════════════════════════════════════╣[/red]
  Endpoints         : [cyan]{len(endpoints)}[/cyan]
  Vulnérab. total   : [cyan]{len(vulnerabilities)}[/cyan]
  Critiques         : [red]{critiques}[/red]
  Hautes            : [yellow]{hautes}[/yellow]
  Business Logic    : [cyan]{bl_count}[/cyan]
  Chaînes IA        : [red]{len(chains)}[/red]
  Score             : [{score_color}]{score}/10[/{score_color}]
  Risque            : [{score_color}]{risk}[/{score_color}]
[red]╚══════════════════════════════════════════╝[/red]
    """)

    console.print(f"[green]📄 Rapport HTML : {html_path}[/green]")
    console.print(f"[green]📄 Rapport JSON : {json_path}[/green]")

if __name__ == "__main__":
    main()
