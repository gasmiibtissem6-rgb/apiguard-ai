import sys
import os
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

sys.path.insert(0, os.path.dirname(__file__))

from core.discovery import APIDiscovery
from core.scanner import VulnerabilityScanner
from core.reporter import Reporter
from ai.analyzer import AIAnalyzer

try:
    from core.crapi_scanner import CRAPIScanner
    CRAPI_AVAILABLE = True
except:
    CRAPI_AVAILABLE = False

console = Console()

BANNER = """
╔══════════════════════════════════════════╗
║        🛡️  APIGuard AI v2.0              ║
║   Professional API Security Scanner      ║
║   OWASP API Top 10 + AI Analysis         ║
╚══════════════════════════════════════════╝
"""

def main():
    console.print(Panel(Text(BANNER, style="bold cyan"), border_style="blue"))

    if len(sys.argv) < 2:
        console.print("[yellow]Usage: python3 main.py <URL> [token JWT][/yellow]")
        console.print("[yellow]Exemple: python3 main.py https://api.example.com eyJhbGci...[/yellow]")
        sys.exit(1)

    target = sys.argv[1]
    token = sys.argv[2] if len(sys.argv) > 2 else None

    if token:
        console.print(f"[green][*] Mode authentifié — token JWT fourni[/green]")

    console.print(f"[bold green][*] Cible: {target}[/bold green]\n")

    console.print(Panel("[bold]Étape 1/3 — Découverte des endpoints[/bold]", style="blue"))
    discovery = APIDiscovery(target)
    endpoints = discovery.run()

    if not endpoints:
        console.print("[red][-] Aucun endpoint découvert.[/red]")
        sys.exit(1)

    console.print(Panel("[bold]Étape 2/3 — Scan de vulnérabilités[/bold]", style="yellow"))
    scanner = VulnerabilityScanner(target, auth_token=token)
    vulnerabilities = scanner.run(endpoints)

    # Scan spécialisé crAPI si token disponible
    if token and CRAPI_AVAILABLE:
        console.print(Panel("[bold]Scan spécialisé crAPI...[/bold]", style="cyan"))
        crapi = CRAPIScanner(target, token)
        extra_vulns = crapi.run()
        vulnerabilities.extend(extra_vulns)

    console.print(Panel("[bold]Étape 3/3 — Analyse IA[/bold]", style="magenta"))
    analyzer = AIAnalyzer(target)
    analysis = analyzer.analyze(vulnerabilities, endpoints)

    reporter = Reporter(target, vulnerabilities, analysis, endpoints)
    html_path, json_path = reporter.run()

    score = analysis.get("global_risk_score", 0)
    risk = analysis.get("risk_level", "N/A")
    score_color = "red" if score >= 8 else "yellow" if score >= 5 else "green"

    critiques = sum(1 for v in vulnerabilities if v['severity'] == 'CRITIQUE')
    hautes = sum(1 for v in vulnerabilities if v['severity'] == 'HAUT')

    console.print(f"""
╔══════════════════════════════════════╗
║           SCAN TERMINÉ v2.0          ║
╠══════════════════════════════════════╣
║  Endpoints : {len(endpoints):<26}║
║  Vulnérab. : {len(vulnerabilities):<26}║
║  Critiques : [{score_color}]{critiques}[/{score_color}]{' '*(25-len(str(critiques)))}║
║  Hautes    : {hautes:<26}║
║  Score     : [{score_color}]{score}/10[/{score_color}]{' '*(25-len(str(score)))}║
║  Risque    : [{score_color}]{risk}[/{score_color}]{' '*(26-len(risk))}║
╚══════════════════════════════════════╝
    """)
    console.print(f"[green]📄 Rapport HTML : {html_path}[/green]")
    console.print(f"[green]📄 Rapport JSON : {json_path}[/green]")

if __name__ == "__main__":
    main()
