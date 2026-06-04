import httpx
import json
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

class APIDiscovery:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.found_endpoints = []
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; APIGuard/2.0)',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
        }

    def load_wordlist(self):
        # Essayer SecLists d'abord (pro), sinon wordlist locale
        seclists_paths = [
            '/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt',
            '/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt',
            '/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt',
        ]
        for path in seclists_paths:
            try:
                with open(path, 'r', errors='ignore') as f:
                    words = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                    # Limiter à 2000 pour la vitesse
                    console.print(f"[green][+] SecLists chargé: {path} ({len(words)} entrées)[/green]")
                    return words[:2000]
            except:
                continue
        # Fallback wordlist locale
        try:
            with open('wordlists/api_endpoints.txt', 'r') as f:
                return [l.strip() for l in f if l.strip()]
        except:
            return ['/api', '/api/v1', '/api/v2', '/users', '/admin']

    def check_endpoint(self, endpoint, method='GET'):
        if not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        url = f"{self.target}{endpoint}"
        try:
            r = httpx.request(
                method, url,
                headers=self.headers,
                timeout=6,
                follow_redirects=False,
                verify=False
            )
            # Ignorer 404 vides
            if r.status_code == 404 and len(r.content) < 150:
                return None
            # Ignorer redirections vers page d'accueil
            if r.status_code in [301, 302]:
                location = r.headers.get('location', '')
                if location in ['/', '/index.html', self.target]:
                    return None

            return {
                'url': url,
                'endpoint': endpoint,
                'status': r.status_code,
                'size': len(r.content),
                'content_type': r.headers.get('content-type', ''),
                'server': r.headers.get('server', ''),
                'x_powered_by': r.headers.get('x-powered-by', ''),
                'is_json': 'json' in r.headers.get('content-type', ''),
                'response': r.text[:800],
                'headers': dict(r.headers),
                'method': method
            }
        except:
            return None

    def detect_swagger(self):
        swagger_paths = [
            '/swagger.json', '/swagger.yaml', '/swagger/v1/swagger.json',
            '/openapi.json', '/openapi.yaml', '/openapi/v3/api-docs',
            '/api/docs', '/api/swagger', '/api/openapi',
            '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json',
            '/api-docs', '/api-docs/swagger.json',
            '/spec', '/api/spec', '/docs/api',
        ]
        console.print("[cyan][*] Recherche documentation Swagger/OpenAPI...[/cyan]")
        for path in swagger_paths:
            url = f"{self.target}{path}"
            try:
                r = httpx.get(url, headers=self.headers, timeout=6,
                             follow_redirects=True, verify=False)
                if r.status_code == 200 and len(r.content) > 100:
                    console.print(f"[green][+] Swagger trouvé: {url}[/green]")
                    self.parse_swagger(r.text, path)
            except:
                pass

    def parse_swagger(self, content, base_path):
        try:
            data = json.loads(content)
            paths = data.get('paths', {})
            servers = data.get('servers', [])
            base = ''
            if servers:
                base = servers[0].get('url', '')
                if base.startswith('http'):
                    base = ''

            for path, methods in paths.items():
                full_path = base + path
                ep = {
                    'url': f"{self.target}{full_path}",
                    'endpoint': full_path,
                    'status': 200,
                    'size': 0,
                    'content_type': 'application/json',
                    'server': '',
                    'x_powered_by': '',
                    'is_json': True,
                    'response': '',
                    'headers': {},
                    'methods': list(methods.keys()),
                    'from_swagger': True,
                    'parameters': []
                }
                # Extraire les paramètres
                for method, details in methods.items():
                    params = details.get('parameters', [])
                    ep['parameters'].extend([p.get('name') for p in params])

                self.found_endpoints.append(ep)
                console.print(f"[green][+] Swagger: {full_path} [{', '.join(list(methods.keys())).upper()}][/green]")
        except Exception as e:
            pass

    def detect_framework(self):
        """Détecter le framework pour adapter la wordlist"""
        try:
            r = httpx.get(self.target, headers=self.headers, timeout=6, verify=False)
            server = r.headers.get('server', '').lower()
            powered = r.headers.get('x-powered-by', '').lower()
            content = r.text.lower()

            if 'django' in powered or 'django' in content:
                return 'django'
            elif 'laravel' in powered or 'laravel' in content:
                return 'laravel'
            elif 'express' in powered or 'node' in powered:
                return 'express'
            elif 'spring' in powered or 'java' in server:
                return 'spring'
            elif 'rails' in powered:
                return 'rails'
        except:
            pass
        return 'generic'

    def fuzz_endpoints(self):
        wordlist = self.load_wordlist()
        framework = self.detect_framework()
        console.print(f"[cyan][*] Framework détecté: {framework}[/cyan]")
        console.print(f"[cyan][*] Fuzzing {len(wordlist)} endpoints...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}[/cyan]"),
            BarColumn(),
            TextColumn("[cyan]{task.completed}/{task.total}[/cyan]"),
            transient=True
        ) as progress:
            task = progress.add_task("Fuzzing...", total=len(wordlist))
            for endpoint in wordlist:
                result = self.check_endpoint(endpoint)
                if result:
                    self.found_endpoints.append(result)
                    status_color = "green" if result['status'] == 200 else "yellow"
                    console.print(
                        f"[{status_color}][+] {result['status']} {result['size']}B → {result['endpoint']}[/{status_color}]"
                    )
                progress.advance(task)

    def run(self):
        console.print(f"\n[yellow][*] Démarrage découverte sur {self.target}[/yellow]")
        self.detect_swagger()
        self.fuzz_endpoints()

        if not self.found_endpoints:
            result = self.check_endpoint('/')
            if result:
                self.found_endpoints.append(result)
                console.print(f"[yellow][~] Endpoint racine ajouté[/yellow]")

        # Dédupliquer
        seen = set()
        unique = []
        for ep in self.found_endpoints:
            if ep['endpoint'] not in seen:
                seen.add(ep['endpoint'])
                unique.append(ep)
        self.found_endpoints = unique

        console.print(f"[green][+] {len(self.found_endpoints)} endpoints uniques découverts[/green]")
        return self.found_endpoints
