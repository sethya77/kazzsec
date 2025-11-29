#!/usr/bin/env python3
"""
Phishing Awareness Simulator (SAFE, local-only)

Purpose:
- Educational phishing simulation for authorized training and lab use only.
- Shows a consent screen, then a simulated login page. Submissions are recorded
  (email + SHA256(password) only) along with timestamp, client IP and user-agent.
- After submission the user is shown an explanation page teaching them what signs
  to look for in real phishing attempts.
- Admin view (protected by an admin key) shows anonymized records for trainers.

Security & Ethics (READ BEFORE RUNNING):
- Use this tool **only** in environments where you have explicit permission to run simulations.
- Do **not** deploy this on public-facing servers without prior written consent from stakeholders.
- Do **not** collect or store real credentials for real accounts. This tool hashes passwords with SHA256;
  however, **do not** use it to capture actual user credentials. Configure participants to use dummy credentials.
- This tool is intended for training and awareness only.

Run (example):
    pip install flask
    export SIM_ADMIN_KEY=some-secret-key   # or set in Windows: setx SIM_ADMIN_KEY "some-secret-key"
    python phishing_simulator.py

Open in browser:
    http://127.0.0.1:5000/        (consent -> simulated login)
    http://127.0.0.1:5000/admin?key=some-secret-key   (view results)

Files created:
- submissions.csv : saved in same folder as script (timestamp, ip, ua, email, pass_hash)
"""

import os, hashlib, csv, datetime
from flask import Flask, request, render_template_string, redirect, url_for, abort, send_file

APP_DIR = os.path.dirname(os.path.abspath(__file__))
SUBMISSIONS_FILE = os.path.join(APP_DIR, "submissions.csv")
ADMIN_KEY_ENV = "SIM_ADMIN_KEY"  # admin key must be set as environment variable

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret')

CONSENT_HTML = r"""
<!doctype html>
<title>Phishing Simulation — Consent</title>
<h2>Phishing Awareness Simulation — Authorized Use Only</h2>
<p>This simulation is for <b>training and awareness</b> purposes only. Do not enter real credentials.
By continuing you acknowledge that this is a test and you consent to your (dummy) submission being recorded for training.</p>
<form method="post" action="{{ url_for('login_sim') }}">
  <label><input type="checkbox" name="consent" value="yes" required> I consent and will use dummy credentials</label><br><br>
  <button type="submit">Proceed to Simulated Login</button>
</form>
"""

LOGIN_HTML = r"""
<!doctype html>
<title>Secure Portal</title>
<h2>Secure Portal (Simulated)</h2>
<p><i>Note: This is a simulated login page for phishing awareness training.</i></p>
<form method="post">
  <label>Email: <input name="email" type="email" required></label><br><br>
  <label>Password: <input name="password" type="password" required></label><br><br>
  <button type="submit">Sign in</button>
</form>
<p style="color:gray;font-size:smaller">Tip: For training, enter a dummy password like 'pass1234' — do not use real credentials.</p>
"""

RESULT_HTML = r"""
<!doctype html>
<title>Simulation Result</title>
<h2>Thank you — This was a simulation</h2>
<p>Your submission has been recorded for training purposes. Below are quick tips to spot phishing:</p>
<ul>
  <li>Check the sender's address carefully (not just the display name).</li>
  <li>Hover links before clicking and check the actual destination.</li>
  <li>Be suspicious of urgent or threatening language asking for credentials.</li>
  <li>Look for mismatched branding, typos, or odd URLs.</li>
</ul>
<p>If this were a real phishing test, your trainer would follow up with guidance.</p>
"""

ADMIN_HTML = r"""
<!doctype html>
<title>Simulator Admin</title>
<h2>Submissions (most recent first)</h2>
<p><a href="{{ url_for('download_csv', key=key) }}">Download CSV</a></p>
<table border="1" cellpadding="6" cellspacing="0">
<tr><th>Timestamp (UTC)</th><th>Client IP</th><th>User-Agent</th><th>Email</th><th>Password SHA256</th></tr>
{% for row in rows %}
<tr>
  <td>{{ row['ts'] }}</td>
  <td>{{ row['ip'] }}</td>
  <td style="max-width:400px;overflow:auto">{{ row['ua'] }}</td>
  <td>{{ row['email'] }}</td>
  <td style="font-family:monospace">{{ row['pass_hash'] }}</td>
</tr>
{% endfor %}
</table>
"""

def ensure_submissions_file():
    if not os.path.exists(SUBMISSIONS_FILE):
        with open(SUBMISSIONS_FILE, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["ts_utc","ip","user_agent","email","password_sha256"])

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

@app.route("/", methods=["GET", "POST"])
def consent():
    if request.method == "POST":
        consent = request.form.get("consent")
        if consent == "yes":
            return redirect(url_for("login_sim"))
        else:
            return "Consent required", 400
    return render_template_string(CONSENT_HTML)

@app.route("/login", methods=["GET", "POST"])
def login_sim():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        pass_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        ip = get_client_ip()
        ua = request.headers.get("User-Agent", "")[:800]
        ensure_submissions_file()
        with open(SUBMISSIONS_FILE, "a", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            ts = datetime.datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            writer.writerow([ts, ip, ua, email, pass_hash])
        return render_template_string(RESULT_HTML)
    return render_template_string(LOGIN_HTML)

@app.route("/admin", methods=["GET"])
def admin():
    key = request.args.get("key") or os.environ.get(ADMIN_KEY_ENV)
    if not key or key != os.environ.get(ADMIN_KEY_ENV):
        abort(403)
    ensure_submissions_file()
    rows = []
    with open(SUBMISSIONS_FILE, "r", encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reversed(list(reader)):
            rows.append({
                "ts": r.get("ts_utc"),
                "ip": r.get("ip"),
                "ua": r.get("user_agent"),
                "email": r.get("email"),
                "pass_hash": r.get("password_sha256"),
            })
    return render_template_string(ADMIN_HTML, rows=rows, key=key)

@app.route("/download", methods=["GET"])
def download_csv():
    key = request.args.get("key") or os.environ.get(ADMIN_KEY_ENV)
    if not key or key != os.environ.get(ADMIN_KEY_ENV):
        abort(403)
    ensure_submissions_file()
    return send_file(SUBMISSIONS_FILE, as_attachment=True, download_name="submissions.csv")

if __name__ == "__main__":
    if not os.environ.get(ADMIN_KEY_ENV):
        print("WARNING: Admin key not set. Generate one and set environment variable SIM_ADMIN_KEY before running in training environments.")
        print("Example (Linux/macOS): export SIM_ADMIN_KEY=your-secret-key")
        print("Windows PowerShell: setx SIM_ADMIN_KEY \"your-secret-key\"")
    ensure_submissions_file()
    app.run(host="127.0.0.1", port=5000, debug=False)
