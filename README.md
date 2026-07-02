# Phish URL Scanner

A defensive URL reputation scanner for cybersecurity portfolios. It checks submitted URLs using:

- VirusTotal API v3
- Spamhaus DBL DNS lookup
- SURBL DNS lookup
- Local URL heuristics

## Safety Note

Do not commit your VirusTotal API key. Store it in a local `.env` file only.

## Setup

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and add your VirusTotal API key:

```env
VT_API_KEY=your_key_here
```

## Run

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## API Usage

```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Disclaimer

This tool is for defensive security education, URL reputation checking, and portfolio demonstration only.
