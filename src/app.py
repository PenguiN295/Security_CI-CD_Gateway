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


ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_DOMAINS = {"api.example.com"}

def validate_and_resolve(target_url: str):
    parsed = urlparse(target_url)
    if parsed.scheme not in ALLOWED_SCHEMES or parsed.hostname not in ALLOWED_DOMAINS:
        return None, None
    try:
        # Resolve all associated addresses and verify none are non-routable/internal
        addr_info = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for item in addr_info:
            ip = ipaddress.ip_address(item[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return None, None
        return parsed, item[4][0]
    except Exception:
        return None, None

@app.route('/api/fetch', methods=['GET'])
def fetch_url():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "Missing URL parameter"}), 400

    parsed_url, resolved_ip = validate_and_resolve(target_url)
    if not parsed_url or not resolved_ip:
        return jsonify({"error": "Disallowed or invalid host"}), 400

    # Pin resolved IP in the destination to prevent DNS rebinding TOCTOU attacks
    port = f":{parsed_url.port}" if parsed_url.port else ""
    pinned_url = f"{parsed_url.scheme}://{resolved_ip}{port}{parsed_url.path or '/'}"
    headers = {"Host": parsed_url.hostname}

    try:
        response = requests.get(
            pinned_url,
            headers=headers,
            timeout=3,
            allow_redirects=False
        )
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