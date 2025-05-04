from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret-key"  # Change this in production

jwt = JWTManager(app)

# Users database (example only)
users = {
    "admin": "admin123",
    "user": "user123"
}

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    if username in users and users[username] == password:
        token = create_access_token(identity=username)
        return jsonify(access_token=token), 200
    return jsonify(msg="Bad credentials"), 401

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    return jsonify(msg="You accessed a protected route"), 200

if __name__ == "__main__":
    app.run(debug=True)
