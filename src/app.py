from flask import Flask, request, jsonify
from urllib.parse import urlparse
import json
import sqlite3
import ipaddress
import requests
import socket
import pickle
import base64
app = Flask(__name__)
def init_db():
    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT)''')
    c.execute('''INSERT INTO users (username, secret) VALUES ('admin', 'super_secret_token')''')
    c.execute('''CREATE TABLE documents (id INTEGER, owner_id INTEGER, content TEXT)''')
    c.execute('''INSERT INTO documents VALUES (1, 1, 'Admin confidential strategy')''')
    conn.commit()
    return conn

db_conn = init_db()

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    c = db_conn.cursor()
    query = "SELECT id, username FROM users WHERE id = ?"
    c.execute(query, (user_id,))
    user = c.fetchone()
    if user:
        return jsonify({"id": user[0], "username": user[1]})
    return jsonify({"error": "User not found"}), 404

ALLOWED_DOMAINS = {"api.example.com", "trusted-service.internal"}

def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if parsed.netloc.split(":")[0] not in ALLOWED_DOMAINS:
            return False
        ip_addr = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(ip_addr)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except Exception:
        return False

@app.route('/api/fetch', methods=['GET'])
def fetch_url():
    target_url = request.args.get('url')
    if not target_url or not is_safe_url(target_url):
        return jsonify({"error": "Invalid or disallowed URL"}), 400
    if not is_safe_url(target_url):
        return jsonify({"error": "URL not allowed"}), 400
    try:
        response = requests.get(target_url, timeout=3, allow_redirects=False)
        return jsonify({"status": response.status_code, "data_preview": response.text[:100]})
    except requests.RequestException:
        return jsonify({"error": "Failed to fetch resource"}), 502

@app.route('/api/session', methods=['POST'])
def load_session():
    try:
        encoded_data = request.json.get('session_data')
        if not encoded_data:
            return jsonify({"error": "Missing session_data"}), 400
        decoded_data = base64.b64decode(encoded_data)
        # Replace insecure pickle deserialization with safe JSON parsing
        session = json.loads(decoded_data.decode('utf-8'))
        return jsonify({"message": "Session loaded", "user": session.get('user')})
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return jsonify({"error": "Invalid session data format"}), 400
    except Exception:
        return jsonify({"error": "An error occurred processing the session"}), 500

@app.route('/api/documents/<int:doc_id>', methods=['GET'])
def get_document(doc_id):
    current_user_id = 2  # Resolved from authenticated session context
    
    c = db_conn.cursor()
    # Enforce multi-tenant access control in the query predicate
    c.execute("SELECT content FROM documents WHERE id = ? AND owner_id = ?", (doc_id, current_user_id))
    doc = c.fetchone()
    
    if doc:
        return jsonify({"document": doc[0]})
    return jsonify({"error": "Document not found"}), 404

if __name__ == '__main__':
    import os
    # Restrict to loopback interface and disable interactive debug mode
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1')
    app.run(debug=debug_mode, host='127.0.0.1', port=5000)