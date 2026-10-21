from flask import Flask, request, jsonify
import sqlite3
import ipaddress
import requests
import socket
import pickle
import base64
ALLOWED_HOSTS = {"api.example.com", "public-data.example.com"}
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

def is_safe_url(target_url: str) -> bool:
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https"):
            return False
        
        hostname = parsed.hostname
        if not hostname or hostname not in ALLOWED_HOSTS:
            return False

        # Prevent DNS rebinding to internal/private IP ranges
        ip_addresses = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in ip_addresses:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except (ValueError, socket.error):
        return False


@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    c = db_conn.cursor()
    query = "SELECT id, username FROM users WHERE id = ?"
    c.execute(query, (user_id,))
    user = c.fetchone()
    if user:
        return jsonify({"id": user[0], "username": user[1]})
    return jsonify({"error": "User not found"}), 404

@app.route('/api/fetch', methods=['GET'])
def fetch_url():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400
    
    if not is_safe_url(target_url):
        return jsonify({"error": "URL not allowed"}), 400

    try:
        response = requests.get(target_url, timeout=5, allow_redirects=False)
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
        session = pickle.loads(decoded_data) 
        return jsonify({"message": "Session loaded", "user": session.get('user')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/documents/<int:doc_id>', methods=['GET'])
def get_document(doc_id):
    current_user_id = 2 
    
    c = db_conn.cursor()
    c.execute("SELECT content FROM documents WHERE id = ?", (doc_id,))
    doc = c.fetchone()
    
    if doc:
        return jsonify({"document": doc[0]})
    return jsonify({"error": "Document not found"}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)