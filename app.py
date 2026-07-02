from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import validators

from scanner.virustotal import get_url_report
from scanner.dnsbl import check_blocklists
from scanner.heuristics import analyze_url_heuristics
from scanner.scoring import calculate_score

load_dotenv()

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_url():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url", "").strip()

    if not url or not validators.url(url):
        return jsonify({"error": "Please submit a valid full URL, including http:// or https://"}), 400

    vt = get_url_report(url)
    blocklists = check_blocklists(url)
    heuristics = analyze_url_heuristics(url)
    verdict = calculate_score(vt, blocklists, heuristics)

    return jsonify({
        "url": url,
        "verdict": verdict,
        "virustotal": vt,
        "blocklists": blocklists,
        "heuristics": heuristics,
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
