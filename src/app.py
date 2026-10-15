from flask import Flask, request, jsonify
import sqlite3
import requests
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

# --- VULNERABILITY 1: SQL Injection (SQLi) ---
# Flaw: String formatting directly into the query execution.
@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    c = db_conn.cursor()
    # Semgrep will flag this raw concatenation
    query = f"SELECT id, username FROM users WHERE id = {user_id}"
    c.execute(query)
    user = c.fetchone()
    if user:
        return jsonify({"id": user[0], "username": user[1]})
    return jsonify({"error": "User not found"}), 404

# --- VULNERABILITY 2: Server-Side Request Forgery (SSRF) ---
# Flaw: Fetching a user-provided URL without an allowlist or domain validation.
@app.route('/api/fetch', methods=['GET'])
def fetch_url():
    target_url = request.args.get('url')
    if not target_url:
        return jsonify({"error": "URL parameter required"}), 400
    
    # Semgrep will flag this unvalidated request
    response = requests.get(target_url)
    return jsonify({"status": response.status_code, "data_preview": response.text[:100]})

# --- VULNERABILITY 3: Insecure Deserialization ---
# Flaw: Unpickling untrusted data from a user payload.
@app.route('/api/session', methods=['POST'])
def load_session():
    try:
        encoded_data = request.json.get('session_data')
        if not encoded_data:
            return jsonify({"error": "Missing session_data"}), 400
        
        # Semgrep will flag the use of pickle.loads on user input
        decoded_data = base64.b64decode(encoded_data)
        session = pickle.loads(decoded_data) 
        return jsonify({"message": "Session loaded", "user": session.get('user')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- VULNERABILITY 4: Broken Access Control (IDOR) ---
# Flaw: Fetching a document by ID without verifying if the requesting user owns it.
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