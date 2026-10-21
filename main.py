from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import subprocess
import joblib
import pandas as pd
import os
import re
import platform
from datetime import datetime, timedelta
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey123"

# -----------------------
# Files
# -----------------------
ML_ALERT_FILE = "ml_alerts.csv"
SCAN_LOG_FILE = "scan_log.csv"

# -----------------------
# Time helper
# -----------------------
def get_kl_time():
    """Current time in Kuala Lumpur (UTC+8)."""
    return datetime.utcnow() + timedelta(hours=8)

# -----------------------
# Admin credentials
# -----------------------
ADMIN_EMAIL = "admin@cyscan.com"
ADMIN_PASSWORD = "12345"

# -----------------------
# Load ML model (robust path)
# -----------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def find_model_path(filename="risk_model.pkl"):
    """Search common locations for the model file."""
    candidates = [
        os.path.join(BASE_DIR, filename),               # same folder as main.py (recommended)
        os.path.join(BASE_DIR, "model", filename),
        os.path.join(BASE_DIR, "models", filename),
        r"C:\cyscan\risk_model.pkl",                    # your previous hardcoded path
        r"C:\Users\ACER\Documents\FYP\Coding FYP\risk_model.pkl",  # possible local folder
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None, candidates

MODEL_PATH = find_model_path()
if isinstance(MODEL_PATH, tuple):
    found_path, checked = MODEL_PATH
    if not found_path:
        msg = (
            "❌ Model file not found.\n\n"
            "Checked these locations:\n"
            + "\n".join([f"- {c}" for c in checked])
            + "\n\n✅ Fix: Put 'risk_model.pkl' in the SAME folder as main.py, or update MODEL_PATH."
        )
        raise FileNotFoundError(msg)
    MODEL_PATH = found_path

risk_model = joblib.load(MODEL_PATH)
print(f"✅ ML model loaded successfully from: {MODEL_PATH}")

# -----------------------
# (Optional) action model placeholders (kept, but not loaded)
# -----------------------
ml_action_model = None
ml_action_vectorizer = None

def predict_action(reason: str, confidence: float) -> str:
    """Predict or infer suggested action from ML model or rule-based fallback."""
    text = f"{reason} confidence:{confidence}"
    if ml_action_model and ml_action_vectorizer:
        X = ml_action_vectorizer.transform([text])
        return ml_action_model.predict(X)[0]

    reason_l = (reason or "").lower()
    if "scan" in reason_l or "malware" in reason_l or confidence > 90:
        return "Terminate"
    elif "upload" in reason_l or "login" in reason_l or confidence > 60:
        return "Monitor"
    else:
        return "Ignore"

# -----------------------
# Nmap path helpers
# -----------------------
def get_nmap_path():
    if platform.system().lower().startswith("win"):
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe"
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
    return "nmap"

NMAP = get_nmap_path()

# -----------------------
# Feature extraction (dummy)
# NOTE: You should replace this with real features that match your trained model input columns.
# -----------------------
def extract_features(ip: str, ports: list) -> pd.DataFrame:
    rows = []

    BAD_FEATURES = {
        "Flow Duration": 44,
        "Total Fwd Packets": 1,
        "Fwd Packet Length Mean": 2.0,
        "SYN Flag Count": 0,
        "RST Flag Count": 0,
        "Packet Length Mean": 3.33,
    }

    GOOD_FEATURES = {
        "Flow Duration": 5000000,
        "Total Fwd Packets": 40,
        "Fwd Packet Length Mean": 64.0,
        "SYN Flag Count": 0,
        "RST Flag Count": 1,
        "Packet Length Mean": 110.0,
    }

    DANGEROUS_PORTS = [21, 22, 23, 80, 445, 3389]

    for p in ports:
        rows.append(BAD_FEATURES if p in DANGEROUS_PORTS else GOOD_FEATURES)

    df = pd.DataFrame(rows)

    # IMPORTANT: ensure the dataframe columns match the training columns exactly.
    return df

# -----------------------
# Nmap scanning
# -----------------------
def run_nmap(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)

def parse_open_ports(nmap_stdout: str, expect_proto: str) -> list:
    open_ports = []
    for line in nmap_stdout.splitlines():
        m = re.match(r"^\s*(\d{1,5})/(tcp|udp)\s+open\b", line.strip(), re.IGNORECASE)
        if m:
            port = int(m.group(1))
            proto = m.group(2).lower()
            if proto == expect_proto:
                open_ports.append(port)
    return sorted(list(set(open_ports)))

def scan_ports(ip: str, protocol: str, port_mode: str, custom_ports: str | None) -> list:
    cmd = [NMAP, "-Pn"]

    if protocol == "udp":
        cmd += ["-sU"]
        expect_proto = "udp"
    else:
        cmd += ["-sS"]
        expect_proto = "tcp"

    if port_mode == "custom" and custom_ports:
        cmd += ["-p", custom_ports]
    else:
        cmd += ["-F"]

    cmd += [ip]
    result = run_nmap(cmd)

    # Fallback for TCP SYN scan needing admin/root
    if protocol == "tcp" and ("requires root" in (result.stderr or "").lower() or result.returncode != 0):
        cmd_fallback = [arg if arg != "-sS" else "-sT" for arg in cmd]
        result = run_nmap(cmd_fallback)

    if result.returncode != 0 and not result.stdout:
        raise RuntimeError(f"Nmap failed.\nCMD: {' '.join(cmd)}\nSTDERR:\n{result.stderr}")

    return parse_open_ports(result.stdout, expect_proto)

# -----------------------
# Logging (CSV)
# -----------------------
def log_scan_csv(ip, ports, risk_labels):
    df = pd.DataFrame({
        "timestamp": [get_kl_time().strftime("%Y-%m-%d %H:%M:%S")],
        "ip": [ip],
        "open_ports": [len(ports)],
        "high_risk": [sum(1 for r in risk_labels if r == "High Risk")],
        "user": ["admin"],
    })
    if not os.path.exists(SCAN_LOG_FILE):
        df.to_csv(SCAN_LOG_FILE, index=False)
    else:
        df.to_csv(SCAN_LOG_FILE, mode="a", header=False, index=False)

# -----------------------
# Alerts (CSV)
# -----------------------
def add_ml_alert(ip, confidence, reason, action):
    if confidence > 90:
        severity = "High"
    elif confidence > 75:
        severity = "Medium"
    else:
        severity = "Low"

    attack_cat = "Port Scan / Reconnaissance"
    dur = "N/A"
    sbytes = "N/A"
    dbytes = "N/A"

    columns = ["ip", "confidence", "severity", "action", "reason", "attack_cat", "dur", "sbytes", "dbytes"]
    df_new = pd.DataFrame([[ip, confidence, severity, action, reason, attack_cat, dur, sbytes, dbytes]], columns=columns)

    if os.path.exists(ML_ALERT_FILE):
        df_new.to_csv(ML_ALERT_FILE, mode="a", header=False, index=False)
    else:
        df_new.to_csv(ML_ALERT_FILE, index=False)

def generate_scan_report(ip, ports, risk_labels, confidence, action_suggested):
    if not os.path.exists("reports"):
        os.makedirs("reports")

    high_risk_count = sum(1 for r in risk_labels if r == "High Risk")

    if action_suggested == "Terminate":
        summary = "CRITICAL THREAT DETECTED"
        advice = (
            f"The system detected {high_risk_count} high-risk ports potentially involved in malicious activity.\n"
            f"RECOMMENDATION: Immediately BLOCK this IP via Firewall or close ports {ports}."
        )
    elif action_suggested == "Monitor":
        summary = "SUSPICIOUS ACTIVITY"
        advice = (
            f"Unusual traffic patterns detected with {confidence}% confidence.\n"
            f"RECOMMENDATION: Monitor this IP closely."
        )
    else:
        summary = "SAFE/NORMAL"
        advice = (
            "Traffic patterns appear normal.\n"
            "RECOMMENDATION: No action required."
        )

    filename = f"reports/Report_{ip.replace('.','_')}.txt"
    timestamp = get_kl_time().strftime("%Y-%m-%d %H:%M:%S")

    content = f"""
=========================================================
            CYSCAN SECURITY REPORT
=========================================================
Target IP : {ip}
Date Generated : {timestamp}
Risk Confidence : {confidence}%
Status : {summary}
=========================================================

FINDINGS:
- Open Ports Found : {ports}
- Risk Assessment : {risk_labels}

---------------------------------------------------------
AI-GENERATED ADVICE:
---------------------------------------------------------
{advice}

SUGGESTED ACTION: [{action_suggested}]
=========================================================
This report is auto-generated by Cyscan ML Engine.
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

# -----------------------
# SQLite DB Setup
# -----------------------
DATABASE = "contact_messages.db"
SCAN_DB = "scan_logs.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_scan_db_connection():
    conn = sqlite3.connect(SCAN_DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstName TEXT NOT NULL,
            lastName TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT,
            subject TEXT,
            message TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def init_scan_db():
    conn = get_scan_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            scanned_ip TEXT NOT NULL,
            open_ports_found TEXT,
            action_taken TEXT,
            open_ports_count INTEGER,
            is_high_risk INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()
init_scan_db()

def log_scan_to_db(ip, ports: list, risk_labels: list):
    conn = get_scan_db_connection()
    kl_time = get_kl_time().strftime("%Y-%m-%d %H:%M:%S")

    open_ports_str = ", ".join([str(p) for p in ports])
    open_ports_count = len(ports)

    if "High Risk" in risk_labels:
        action = "Blocked"
        is_high_risk = 1
    elif "Medium Risk" in risk_labels:
        action = "Alerted"
        is_high_risk = 0
    else:
        action = "Logged"
        is_high_risk = 0

    try:
        conn.execute("""
            INSERT INTO scan_history (timestamp, scanned_ip, open_ports_found, action_taken, open_ports_count, is_high_risk)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (kl_time, ip, open_ports_str, action, open_ports_count, is_high_risk))
        conn.commit()
    finally:
        conn.close()

# -----------------------
# ROUTES (Public)
# -----------------------
@app.route("/", methods=["GET"])
def home():
    scroll = request.args.get("scroll")
    if scroll == "about":
        return render_template("user.html", active_page="about")
    return render_template("user.html", active_page="home")

@app.route("/scan", methods=["POST"])
def scan():
    ip = (request.form.get("ip", "") or "").strip()
    protocol = (request.form.get("protocol", "tcp") or "tcp").strip().lower()
    port_mode = (request.form.get("port_mode", "common") or "common").strip().lower()
    custom_ports = request.form.get("custom_ports", "") or ""

    if not ip:
        return render_template("user.html", active_page="home", msg="Please provide an IP address.", result=[])

    try:
        ports = scan_ports(ip, protocol, port_mode, custom_ports)
    except Exception as e:
        return render_template("user.html", active_page="home", msg=f"Scan error: {e}", result=[], ip=ip)

    if not ports:
        return render_template("user.html", active_page="home", msg="No open ports found.", result=[], ip=ip)

    df = extract_features(ip, ports)

    try:
        preds = risk_model.predict(df)
        print(f"MODEL PREDICTION RAW: {preds}")
    except Exception as e:
        return render_template("user.html", active_page="home", msg=f"Prediction error: {e}", result=[], ip=ip)

    id2label = {0: "Low Risk", 1: "Medium Risk", 2: "High Risk"}

    result = []
    risk_labels = []
    for p, pr in zip(ports, preds):
        label = id2label.get(int(pr), str(pr))
        result.append({"port": p, "risk": label})
        risk_labels.append(label)

    # Log scan to CSV + DB
    log_scan_csv(ip, ports, risk_labels)
    log_scan_to_db(ip, ports, risk_labels)

    # Confidence + action suggestion
    high_risk_count = sum(1 for r in risk_labels if r == "High Risk")
    if len(risk_labels) > 0:
        raw_conf = (high_risk_count / len(risk_labels)) * 100
        confidence = max(raw_conf, 95.0) if high_risk_count > 0 else 10.0
    else:
        confidence = 0.0
    confidence = round(confidence, 2)

    if high_risk_count > 0:
        reason = f"Critical: {high_risk_count} dangerous ports found."
        action_suggested = "Terminate"
    elif "Medium Risk" in risk_labels:
        reason = "Warning: Unusual port activity detected."
        action_suggested = "Monitor"
    else:
        reason = "Safe: Normal traffic pattern."
        action_suggested = "Ignore"

    add_ml_alert(ip, confidence, reason, action_suggested)

    try:
        generate_scan_report(ip, ports, risk_labels, confidence, action_suggested)
    except Exception as e:
        print(f"Error generating report: {e}")

    return render_template("user.html", active_page="home", result=result, ip=ip)

@app.route("/demo")
def demo():
    return render_template("steps/demo.html", active_page="demo")

@app.route("/step/<int:step_num>")
def step(step_num):
    return render_template(f"steps/step{step_num}.html", step_num=step_num)

@app.route("/faq")
def faq():
    return render_template("faq.html", active_page="faq")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        firstName = request.form.get("firstName")
        lastName = request.form.get("lastName")
        email = request.form.get("email")
        phone = request.form.get("phone")
        subjects = request.form.getlist("subject[]")
        message = request.form.get("message")

        subject_str = ", ".join(subjects)

        conn = get_db_connection()
        conn.execute("""
            INSERT INTO messages (firstName, lastName, email, phone, subject, message)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (firstName, lastName, email, phone, subject_str, message))
        conn.commit()
        conn.close()

        flash("✅ Your message has been sent!")
        return redirect(url_for("contact"))

    return render_template("contact.html", active_page="contact")

# -----------------------
# ADMIN ROUTES
# -----------------------
@app.route("/admin", methods=["GET"])
def admin():
    return render_template("admin.html")

@app.route("/admin_login", methods=["POST"])
def admin_login():
    email = request.form["email"]
    password = request.form["password"]

    if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return redirect(url_for("dashboard"))
    flash("Invalid email or password. Please try again.", "error")
    return redirect(url_for("admin"))

@app.route("/dashboard")
def dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    if os.path.exists(SCAN_LOG_FILE):
        df = pd.read_csv(SCAN_LOG_FILE)
        today = datetime.now().strftime("%Y-%m-%d")
        total_scans_today = len(df[df["timestamp"].astype(str).str.startswith(today)])
        open_ports_total = int(df["open_ports"].sum())
        suspicious_scans = int(df["high_risk"].sum())
        active_users = df["user"].nunique()
    else:
        total_scans_today = open_ports_total = suspicious_scans = active_users = 0

    return render_template(
        "dashboard.html",
        total_scans_today=total_scans_today,
        open_ports_total=open_ports_total,
        suspicious_scans=suspicious_scans,
        active_users=active_users
    )

@app.route("/admin/logs_history")
def logscan():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    conn = get_scan_db_connection()
    data = conn.execute("""
        SELECT id, timestamp, scanned_ip, open_ports_found, is_high_risk
        FROM scan_history
        ORDER BY timestamp DESC
    """).fetchall()
    conn.close()

    history_list = [dict(row) for row in data]

    for log in history_list:
        full_timestamp = str(log["timestamp"]).split(".")[0]
        try:
            dt_obj = datetime.strptime(full_timestamp, "%Y-%m-%d %H:%M:%S")
            log["date_display"] = dt_obj.strftime("%Y-%m-%d")
            log["time_display"] = dt_obj.strftime("%H:%M:%S")
        except ValueError:
            parts = full_timestamp.split(" ")
            log["date_display"] = parts[0] if len(parts) > 0 else full_timestamp
            log["time_display"] = parts[1] if len(parts) > 1 else ""

    return render_template("logscan.html", history=history_list)

@app.route("/delete_scan_log/<int:log_id>", methods=["POST"])
def delete_scan_log(log_id):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    conn = get_scan_db_connection()
    conn.execute("DELETE FROM scan_history WHERE id = ?", (log_id,))
    conn.commit()
    conn.close()

    flash("✅ Scan log deleted successfully.")
    return redirect(url_for("logscan"))

@app.route("/admin/ml_alert_center")
def ml_alert_center():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    if not os.path.exists(ML_ALERT_FILE):
        return render_template("ml_alert_center.html", alerts=[])

    try:
        df = pd.read_csv(ML_ALERT_FILE)
        df["original_index"] = df.index
        df = df.iloc[::-1]  # newest first
        alerts = df.to_dict(orient="records")
        return render_template("ml_alert_center.html", alerts=alerts)
    except Exception as e:
        print(f"Error loading alerts: {e}")
        return render_template("ml_alert_center.html", alerts=[])

@app.route("/view_report/<ip>")
def view_report(ip):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    filename = f"Report_{ip.replace('.','_')}.txt"
    reports_dir = os.path.join(app.root_path, "reports")
    try:
        return send_from_directory(reports_dir, filename, as_attachment=False)
    except FileNotFoundError:
        return "<h3>Report file not found. Please scan this IP again to generate a report.</h3>"

@app.route("/delete_ml_alert/<int:alert_index>", methods=["POST"])
def delete_ml_alert(alert_index):
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    if os.path.exists(ML_ALERT_FILE):
        try:
            df = pd.read_csv(ML_ALERT_FILE)
            df = df.drop(alert_index)
            df.to_csv(ML_ALERT_FILE, index=False)
            flash("✅ Alert deleted successfully.")
        except Exception as e:
            flash(f"Error deleting alert: {e}", "error")
    return redirect(url_for("ml_alert_center"))

@app.route("/viewdata")
def viewdata():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    conn = get_db_connection()
    data = conn.execute("SELECT * FROM messages ORDER BY id DESC").fetchall()
    conn.close()

    messages_list = [dict(row) for row in data]
    return render_template("viewdata.html", messages=messages_list)

@app.route("/delete_message/<int:message_id>", methods=["POST"])
def delete_message(message_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    conn.commit()
    conn.close()

    flash("🗑️ Message deleted successfully.")
    return redirect(url_for("viewdata"))

@app.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
