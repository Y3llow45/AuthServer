from flask import Flask, request, jsonify
import bcrypt
import os
import firebase_admin
from firebase_admin import credentials, firestore
import json

firebase_config = {
    "type": os.getenv("FIREBASE_TYPE"),
    "project_id": os.getenv("FIREBASE_PROJECT_ID"),
    "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
    "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
    "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
    "client_id": os.getenv("FIREBASE_CLIENT_ID"),
    "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
    "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
    "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_CERT_URL"),
    "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL"),
    "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN")
}
cred = credentials.Certificate(json.loads(json.dumps(firebase_config)))
firebase_admin.initialize_app(cred)
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
