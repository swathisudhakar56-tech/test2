# vulnerable_examples.py
# Intentionally insecure examples for testing SAST/SCA tools.
# WARNING: Run only in isolated test environment.

import os
import sqlite3
import subprocess
import pickle
import xml.etree.ElementTree as ET
from flask import Flask, request, session

# ------------------------------
# 1) SQL Injection (SQLite)
# ------------------------------
def sql_injection_vulnerable(username, db_path=":memory:"):
    """Builds SQL with string interpolation — vulnerable to SQL injection."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # vulnerable: user-controlled username embedded directly
    query = f"SELECT * FROM users WHERE username = '{username}';"
    print("Executing:", query)
    cur.execute(query)  # vulnerable call
    rows = cur.fetchall()
    conn.close()
    return rows

# ------------------------------
# 2) Command Injection / Shell=True
# ------------------------------
def cmd_injection_vulnerable(user_input):
    """Passes user input into a shell=True call."""
    # vulnerable: shell=True with user input
    cmd = f"tar -czf /tmp/archive.tar.gz {user_input}"
    print("Running:", cmd)
    subprocess.run(cmd, shell=True)  # vulnerable

# ------------------------------
# 3) Insecure Deserialization (pickle)
# ------------------------------
def insecure_deserialize_vulnerable(blob):
    """Directly unpickles user-controlled data (remote code execution risk)."""
    # vulnerable: pickle.loads on untrusted data
    obj = pickle.loads(blob)
    return obj

# ------------------------------
# 4) Eval of Untrusted Input
# ------------------------------
def insecure_eval_vulnerable(expr):
    """Evaluates input expression from user — arbitrary code execution."""
    # vulnerable:
    result = eval(expr)   # extremely dangerous on untrusted input
    return result

# ------------------------------
# 5) Hard-coded Credentials
# ------------------------------
# vulnerable: secrets in source
DB_PASSWORD = "P@ssw0rd123"   # hard-coded credential (should never be in source)

def connect_to_db_hardcoded():
    # pretend to connect using hardcoded secret
    print("Connecting to DB with password:", DB_PASSWORD)
    # ... connection code omitted ...

# ------------------------------
# 6) Path Traversal (unsanitized file path)
# ------------------------------
def path_traversal_vulnerable(filename):
    """Opens a user-specified file path without validation."""
    # vulnerable: attacker can pass ../../etc/passwd etc.
    with open(filename, "r") as f:
        return f.read()

# ------------------------------
# 7) Weak Cryptography / Bad Hashing
# ------------------------------
import hashlib

def bad_password_hashing(password):
    """Uses unsalted MD5 for password hashing — weak."""
    # vulnerable: MD5 without salt
    digest = hashlib.md5(password.encode()).hexdigest()
    return digest

# ------------------------------
# 8) Insecure XML parsing (XXE)
# ------------------------------
def insecure_xml_parse(xml_string):
    """
    Uses xml.etree.ElementTree which may process external entities on some parsers.
    Use defusedxml or a parser with external entity resolution disabled.
    """
    root = ET.fromstring(xml_string)   # potential XXE if parser resolves entities
    return root.tag

# ------------------------------
# 9) Insecure Flask app config (debug + hardcoded secret)
# ------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'  # hard-coded secret used for sessions
app.debug = True  # running in debug mode exposes interactive debugger

@app.route("/unsafe-login", methods=["POST"])
def unsafe_login():
    # vulnerable: no rate limiting, no input validation, storing user in session
    username = request.form.get("username")
    session['user'] = username
    return f"Logged in as {username}"

# ------------------------------
# 10) Insecure HTTP client usage (verify=False)
# ------------------------------
import requests

def insecure_http_client(url):
    """Disables TLS verification."""
    # vulnerable: verify=False disables cert validation
    resp = requests.get(url, verify=False)
    return resp.status_code, resp.text[:200]

# ------------------------------
# Example "main" to demonstrate usage (do not run in production)
# ------------------------------
if __name__ == "__main__":
    # Example calls (do not use with real untrusted inputs)
    print("SQL Injection example (vulnerable):")
    print(sql_injection_vulnerable("alice' OR '1'='1"))

    print("\nCommand Injection example (vulnerable):")
    # DO NOT RUN: commented to avoid accidental execution
    # cmd_injection_vulnerable("some_dir; rm -rf /")  

    print("\nInsecure pickle example (vulnerable):")
    # DO NOT RUN with untrusted blob
    # insecure_deserialize_vulnerable(b"...")

    print("\nEval example (vulnerable):")
    # DO NOT RUN: eval can execute arbitrary code
    # print(insecure_eval_vulnerable("__import__('os').system('id')"))

    print("\nHard-coded credentials:", DB_PASSWORD)
    print("Weak hash of 'password':", bad_password_hashing("password"))

    sample_xml = "<root>ok</root>"
    print("XML tag:", insecure_xml_parse(sample_xml))

    # Flask app would be run with: app.run()
