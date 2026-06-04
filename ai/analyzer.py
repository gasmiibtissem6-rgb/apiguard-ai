import json
import httpx
from rich.console import Console

console = Console()

class AIAnalyzer:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.ollama_url = "http://localhost:11434/api/generate"

    def _ai(self, prompt):
        try:
            r = httpx.post(self.ollama_url, json={
                "model": "llama3",
                "prompt": prompt,
                "stream": False
            }, timeout=30)
            if r.status_code == 200:
                return r.json().get("response", "")
        except:
            pass
        return None

    def analyze(self, vulnerabilities, endpoints):
        score = 0
        chains = []
        remediations = []

        severity_scores = {"CRITIQUE": 9, "HAUT": 7, "MOYEN": 4, "BAS": 1}
        for v in vulnerabilities:
            score += severity_scores.get(v.get("severity", "BAS"), 1)

        score = min(10, round(score / max(len(vulnerabilities), 1), 1))

        if score >= 8:
            risk_level = "CRITIQUE"
        elif score >= 6:
            risk_level = "HAUT"
        elif score >= 3:
            risk_level = "MOYEN"
        else:
            risk_level = "BAS"

        # Générer chaînes d'attaque
        bola = [v for v in vulnerabilities if "BOLA" in v["type"]]
        auth = [v for v in vulnerabilities if "AUTH" in v["type"]]
        mass = [v for v in vulnerabilities if "MASS" in v["type"]]

        if bola and auth:
            chains.append({
                "name": "Escalade de privilèges complète",
                "steps": [
                    f"1. Auth bypass sur {auth[0]['endpoint']}",
                    f"2. BOLA sur {bola[0]['endpoint']} → accès admin",
                    "3. Exfiltration de données complète"
                ],
                "severity": "CRITIQUE"
            })

        if mass:
            chains.append({
                "name": "Prise de contrôle de compte",
                "steps": [
                    f"1. Mass assignment sur {mass[0]['endpoint']}",
                    "2. Élévation du rôle vers admin",
                    "3. Accès total à l'application"
                ],
                "severity": "HAUT"
            })

        # Remédiations
        types_found = set(v["type"] for v in vulnerabilities)
        remediation_map = {
            "BOLA/IDOR": "Implémenter vérification ownership côté serveur sur chaque endpoint",
            "AUTH BYPASS": "Valider les tokens JWT côté serveur, rejeter headers non standards",
            "MASS ASSIGNMENT": "Utiliser des DTOs stricts, whitelister les champs acceptés",
            "NO RATE LIMITING": "Ajouter rate limiting (ex: 5 req/min) sur endpoints sensibles",
            "SENSITIVE DATA EXPOSURE": "Masquer les champs sensibles dans les réponses API",
            "SSRF": "Valider et filtrer toutes les URLs fournies par l'utilisateur",
        }
        for t in types_found:
            if t in remediation_map:
                remediations.append(remediation_map[t])

        surface = len(endpoints)
        summary = (
            f"L'API cible présente {len(vulnerabilities)} vulnérabilités sur {surface} endpoints analysés. "
            f"Niveau de risque global: {risk_level} ({score}/10). "
            f"Action immédiate requise sur les failles CRITIQUE."
        )

        ai_prompt = (
            f"Expert sécurité API. Cible: {self.target}. "
            f"Score: {score}/10. Vulnérabilités: "
            f"{json.dumps([{'type':v['type'],'endpoint':v['endpoint']} for v in vulnerabilities[:5]])}. "
            f"Donne un résumé exécutif de 2 phrases pour le management. En français."
        )
        ai_summary = self._ai(ai_prompt)
        if ai_summary:
            summary = ai_summary

        console.print(f"[magenta bold][AI] Score global: {score}/10 ({risk_level})[/magenta bold]")
        return {
            "global_risk_score": score,
            "risk_level": risk_level,
            "attack_chains": chains,
            "executive_summary": summary,
            "prioritized_remediations": remediations,
            "attack_surface": surface,
        }
