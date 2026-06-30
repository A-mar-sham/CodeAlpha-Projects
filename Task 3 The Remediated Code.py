import sqlite3
import os
from flask import Flask, request
from werkzeug.security import check_password_hash

app = Flask(__name__)

# REMEDIATION 1: Load secrets from environment variables, never hardcode them.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default_fallback_key')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        return "Missing credentials", 400

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # REMEDIATION 2: Use parameterized queries (?) to prevent SQL Injection.
    # The database driver safely escapes the inputs.
    query = "SELECT password_hash FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    record = cursor.fetchone()
    conn.close()
    
    # REMEDIATION 3: Verify against a secure password hash (e.g., bcrypt/argon2) 
    # rather than comparing plaintext passwords.
    if record and check_password_hash(record[0], password):
        return "Login successful!"
    else:
        # Use a generic error message to prevent username enumeration
        return "Invalid credentials."