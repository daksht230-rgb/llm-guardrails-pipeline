# Enterprise LLM Safety & Guardrails Pipeline

A high-performance Python framework engineered for real-time LLM safety screening, prompt injection detection, and sensitive data redaction. Designed to safeguard production LLM endpoints against malicious adversarial attacks and privacy leaks.

## Architecture & Core Features
- **Prompt Injection Detection:** Regex-based heuristic engines flagging system overrides and jailbreak attempts.
- **Automated PII Redaction:** Real-time sanitization of sensitive personal data (Emails, Phone numbers, Credit cards).
- **RESTful Safety API:** Built with FastAPI and Pydantic for asynchronous, high-throughput input validation runs.

## Quick Start
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   python main.py
