# README

UniShield AI — AI-based detection of cyber threats in unidirectional IP traffic.

Full documentation:
- `docs/architecture.md` — architecture and data flow.
- `docs/api.md` — API reference.
- `docs/detection.md` — detection pipeline.
- `docs/deployment.md` — deployment and environment.

Quick start:

```bash
pip install -r requirements.txt
cp .env.example .env
python app/main.py
```

Or with Docker:

```bash
docker compose up --build
```

Generate test traffic:

```bash
python scripts/generate_test_traffic.py --fps 50 --duration 5
```