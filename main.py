from flask import Flask, request, jsonify
import bcrypt
import os
import firebase_admin
from firebase_admin import credentials, firestore, initialize_app
import json
import base64

firebase_credentials_base64 = os.getenv('FIREBASE_CREDENTIALS')

if firebase_credentials_base64:
    firebase_credentials_json = base64.b64decode(firebase_credentials_base64).decode('utf-8')
    firebase_config = json.loads(firebase_credentials_json)
    cred = credentials.Certificate(firebase_config)
    initialize_app(cred)
else:
    raise ValueError("Firebase credentials are missing.")
db = firestore.client()

app = Flask(__name__)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400
    
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user_ref = db.collection('users').document(email)
    
    if user_ref.get().exists:
        return jsonify({"error": "User already exists"}), 400
    
    user_ref.set({"email": email, "password": hashed_pw.decode()})
    return jsonify({"message": "User registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    user_ref = db.collection('users').document(email).get()
    if not user_ref.exists:
        return jsonify({"error": "User not found"}), 404
    
    user_data = user_ref.to_dict()
    if bcrypt.checkpw(password.encode(), user_data['password'].encode()):
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid password"}), 401

port = int(os.environ.get("PORT", 5000))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port)
