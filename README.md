# APIGuard AI

AI-powered API security scanner that detects OWASP API Top 10 vulnerabilities and predicts full attack chains using local AI (Ollama/llama3).

## What it does

- Discovers 269+ API endpoints automatically
- Tests OWASP API Top 10 (BOLA, Mass Assignment, Rate Limiting...)
- Business Logic Tester — Race Condition, Price Manipulation, Coupon Abuse
- AI Attack Chain Predictor — maps how vulnerabilities chain into real attacks
- Generates a professional HTML report with risk score

## Real result

Confirmed BOLA/IDOR (CVSS 9.1) on crAPI — a vehicle ID leaked through public posts allowed accessing another user's GPS coordinates using a different token.

## Usage

```bash
pip install httpx flask requests rich colorama
ollama pull llama3
python3 main.py http://target-api.com
python3 main.py http://target-api.com <JWT_TOKEN>
```

## Stack

Python · httpx · Ollama/llama3 · OWASP crAPI

> For authorized use only.
