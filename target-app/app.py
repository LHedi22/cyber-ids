"""
VaultBank — deliberately vulnerable Flask web application.
FOR SECURITY DEMONSTRATION AND IDS TESTING ONLY.
Do NOT deploy in any production or public environment.

Intentional vulnerabilities (by design):
  - SQL injection framing on login (string concat, no parameterisation)
  - No rate limiting on /login
  - No CSRF tokens anywhere
  - Weak, hardcoded secret key (session cookie forgeable)
  - Parameter tampering on /transfer (from_account not authorised)
  - Admin panel bypassable via ?override=true
"""

import os
from flask import Flask, request, session, redirect, url_for, render_template

app = Flask(__name__)
app.secret_key = "vaultbank_secret_2024"      # intentionally weak and public

# ---------------------------------------------------------------------------
# Hardcoded user store (simulates a database table)
# ---------------------------------------------------------------------------
USERS = {
    "admin": {"password": "admin",    "balance": 999999.00, "role": "admin", "name": "Administrator", "acct": "VB-0000-0001"},
    "alice": {"password": "alice123", "balance": 15420.50,  "role": "user",  "name": "Alice Morgan",  "acct": "VB-4872-3901"},
    "bob":   {"password": "bob456",   "balance": 8230.00,   "role": "user",  "name": "Bob Chen",      "acct": "VB-2341-8872"},
}

TRANSACTIONS = {
    "admin": [
        {"id": "TXN-0011", "date": "Apr 25, 2026", "desc": "Reserve Allocation",  "amount":  75000.00, "type": "credit"},
        {"id": "TXN-0010", "date": "Apr 24, 2026", "desc": "Operational Expense", "amount": -12500.00, "type": "debit"},
        {"id": "TXN-0009", "date": "Apr 22, 2026", "desc": "Interest Income",     "amount":   2847.50, "type": "credit"},
        {"id": "TXN-0008", "date": "Apr 20, 2026", "desc": "Compliance Fee",      "amount":  -8000.00, "type": "debit"},
        {"id": "TXN-0007", "date": "Apr 18, 2026", "desc": "Fee Revenue",         "amount":  15420.00, "type": "credit"},
    ],
    "alice": [
        {"id": "TXN-9847", "date": "Apr 25, 2026", "desc": "Netflix Subscription","amount":    -15.99, "type": "debit"},
        {"id": "TXN-9846", "date": "Apr 24, 2026", "desc": "Payroll — Acme Corp", "amount":   4200.00, "type": "credit"},
        {"id": "TXN-9845", "date": "Apr 22, 2026", "desc": "Amazon Marketplace",  "amount":    -89.99, "type": "debit"},
        {"id": "TXN-9844", "date": "Apr 20, 2026", "desc": "ATM Withdrawal",      "amount":   -200.00, "type": "debit"},
        {"id": "TXN-9843", "date": "Apr 18, 2026", "desc": "Freelance Payment",   "amount":    750.00, "type": "credit"},
    ],
    "bob": [
        {"id": "TXN-7712", "date": "Apr 25, 2026", "desc": "Grocery Store",       "amount":   -134.22, "type": "debit"},
        {"id": "TXN-7711", "date": "Apr 23, 2026", "desc": "Payroll — Beta Ltd",  "amount":   3500.00, "type": "credit"},
        {"id": "TXN-7710", "date": "Apr 21, 2026", "desc": "Uber Ride",           "amount":    -23.50, "type": "debit"},
        {"id": "TXN-7709", "date": "Apr 19, 2026", "desc": "Restaurant — Nobu",  "amount":    -67.80, "type": "debit"},
        {"id": "TXN-7708", "date": "Apr 17, 2026", "desc": "Insurance Premium",  "amount":   -450.00, "type": "debit"},
    ],
}

# ---------------------------------------------------------------------------
# Vulnerable authentication — no parameterisation, no rate limiting
# ---------------------------------------------------------------------------

_SQLI_TRIGGERS = ("' or ", "' OR ", '" or ', '" OR ', "--", ";--", "1=1", "or 1", "OR 1", "/*")


def check_login(username: str, password: str):
    """
    Simulates:  SELECT * FROM users WHERE username='{username}' AND password='{password}'

    No parameterisation → SQL injection bypass.
    Inputs like  admin'--  or  ' OR '1'='1  return admin access.
    """
    combined = username + password
    if any(p.lower() in combined.lower() for p in _SQLI_TRIGGERS):
        return "admin"

    if username in USERS and USERS[username]["password"] == password:
        return username
    return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # No rate limiting — unlimited brute force allowed
        result = check_login(username, password)
        if result:
            session["user"] = result
            return redirect(url_for("dashboard"))
        error = "Invalid username or password. Please try again."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    user = session["user"]
    data = USERS.get(user, USERS["alice"])
    txns = TRANSACTIONS.get(user, [])
    return render_template("dashboard.html", user=user, data=data, transactions=txns)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user" not in session:
        return redirect(url_for("login"))
    user = session["user"]
    message = None

    if request.method == "POST":
        # VULNERABLE: from_account is taken from the form body without checking
        # that it matches session["user"] — parameter tampering drains other accounts.
        from_account = request.form.get("from_account", user)
        recipient    = request.form.get("recipient", "")
        memo         = request.form.get("memo", "Transfer")

        try:
            amount = float(request.form.get("amount", "0"))
            # No validation: negative amount reverses the transfer (money creation).
            # No balance check: overdraft freely allowed.
        except ValueError:
            amount = 0.0

        # No CSRF, no authorisation on from_account
        if from_account in USERS:
            USERS[from_account]["balance"] -= amount
        if recipient in USERS:
            USERS[recipient]["balance"] += amount

        ref = f"REF-{abs(hash(from_account + recipient + memo)) % 100000:05d}"
        message = {
            "ok": True,
            "text": f"${amount:,.2f} transferred from {from_account} to {recipient}.",
            "ref": ref,
        }

    return render_template(
        "transfer.html",
        user=user,
        data=USERS.get(user, {}),
        users=USERS,
        message=message,
    )


@app.route("/admin")
def admin():
    if "user" not in session:
        return redirect(url_for("login"))
    user = session["user"]

    # VULNERABLE: ?override=true bypasses the role check entirely
    if USERS.get(user, {}).get("role") != "admin":
        if request.args.get("override") != "true":
            return render_template("denied.html", user=user), 403

    total_balance = sum(u["balance"] for u in USERS.values())
    return render_template(
        "admin.html",
        user=user,
        users=USERS,
        total_balance=total_balance,
        all_transactions=TRANSACTIONS,
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
