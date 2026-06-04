import requests
import json
from rich.console import Console

console = Console()

class AttackChainPredictor:
    def __init__(self):
        self.ollama_url = "http://localhost:11434/api/generate"
        self.model = "llama3"

    def predict(self, vulnerabilities, target):
        console.print("[magenta][*] AI Attack Chain Predictor en cours...[/magenta]")

        if not vulnerabilities:
            return {"chains": [], "summary": "Aucune vulnérabilité détectée"}

        # Préparer les vulnérabilités pour l'IA
        vuln_summary = []
        for v in vulnerabilities:
            vuln_summary.append({
                "type": v.get("type", ""),
                "severity": v.get("severity", ""),
                "endpoint": v.get("endpoint", ""),
                "description": v.get("description", "")[:200],
                "cvss": v.get("cvss", 0)
            })

        prompt = f"""Tu es un expert en cybersécurité offensive spécialisé en API Security.

Analyse ces vulnérabilités détectées sur {target} et génère des chaînes d'attaque réalistes.

VULNÉRABILITÉS DÉTECTÉES:
{json.dumps(vuln_summary, indent=2, ensure_ascii=False)}

Génère EXACTEMENT ce JSON (sans markdown, sans explication):
{{
  "chains": [
    {{
      "id": 1,
      "name": "Nom court de la chaîne",
      "severity": "CRITIQUE|HAUT|MOYEN",
      "probability": 85,
      "impact": "Description de l'impact final",
      "steps": [
        {{
          "step": 1,
          "action": "Action de l'attaquant",
          "vulnerability_used": "Type de vuln utilisée",
          "result": "Résultat obtenu"
        }}
      ],
      "final_impact": "Impact final sur l'organisation",
      "mitigations": ["mitigation 1", "mitigation 2"]
    }}
  ],
  "overall_risk": "CRITIQUE|HAUT|MOYEN|BAS",
  "attack_summary": "Résumé exécutif en 2 phrases"
}}"""

        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                },
                timeout=120
            )

            if response.status_code == 200:
                raw = response.json().get("response", "")
                # Nettoyer la réponse
                raw = raw.strip()
                if "```" in raw:
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                # Trouver le JSON
                start = raw.find("{")
                end = raw.rfind("}") + 1
                if start >= 0 and end > start:
                    json_str = raw[start:end]
                    result = json.loads(json_str)
                    console.print(f"[green][+] {len(result.get('chains', []))} chaînes d'attaque prédites[/green]")
                    return result
        except Exception as e:
            console.print(f"[yellow][~] Erreur IA: {e}[/yellow]")

        # Fallback si IA échoue
        return self._manual_chain(vulnerabilities, target)

    def _manual_chain(self, vulnerabilities, target):
        """Génère des chaînes manuellement si Ollama échoue"""
        chains = []
        
        has_bola = any(v.get("type") == "BOLA/IDOR" for v in vulnerabilities)
        has_sensitive = any(v.get("type") == "SENSITIVE DATA EXPOSURE" for v in vulnerabilities)
        has_ratelimit = any(v.get("type") == "NO RATE LIMITING" for v in vulnerabilities)
        has_mass = any(v.get("type") == "MASS ASSIGNMENT" for v in vulnerabilities)

        if has_sensitive and has_bola:
            chains.append({
                "id": 1,
                "name": "Data Leak → GPS Tracking",
                "severity": "CRITIQUE",
                "probability": 90,
                "impact": "Localisation GPS d'utilisateurs exposée",
                "steps": [
                    {
                        "step": 1,
                        "action": "Récupérer vehicleId depuis posts publics",
                        "vulnerability_used": "SENSITIVE DATA EXPOSURE",
                        "result": "UUID véhicule d'un autre utilisateur obtenu"
                    },
                    {
                        "step": 2,
                        "action": "Accéder à /vehicle/{uuid}/location",
                        "vulnerability_used": "BOLA/IDOR",
                        "result": "Coordonnées GPS réelles de la victime"
                    },
                    {
                        "step": 3,
                        "action": "Tracking temps réel de la victime",
                        "vulnerability_used": "BOLA/IDOR",
                        "result": "Surveillance physique possible"
                    }
                ],
                "final_impact": "Violation grave de la vie privée — localisation physique des utilisateurs",
                "mitigations": [
                    "Supprimer vehicleId des réponses publiques",
                    "Vérifier ownership avant accès /location",
                    "Implémenter contrôle d'accès RBAC"
                ]
            })

        if has_ratelimit and has_mass:
            chains.append({
                "id": 2,
                "name": "Brute Force → Privilege Escalation",
                "severity": "HAUT",
                "probability": 75,
                "impact": "Compte admin compromis",
                "steps": [
                    {
                        "step": 1,
                        "action": "Brute force sur /auth/login",
                        "vulnerability_used": "NO RATE LIMITING",
                        "result": "Credentials valides obtenus"
                    },
                    {
                        "step": 2,
                        "action": "Signup avec role=admin",
                        "vulnerability_used": "MASS ASSIGNMENT",
                        "result": "Compte avec privilèges élevés créé"
                    }
                ],
                "final_impact": "Accès administrateur complet à l'application",
                "mitigations": [
                    "Ajouter rate limiting (5 req/min)",
                    "Whitelist des champs autorisés au signup"
                ]
            })

        return {
            "chains": chains,
            "overall_risk": "CRITIQUE" if chains else "MOYEN",
            "attack_summary": f"{len(chains)} chaînes d'attaque identifiées sur {target}"
        }
