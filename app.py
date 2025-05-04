from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import timedelta

# Initialisation de l'application Flask
app = Flask(__name__)

# Configuration de la base de données et de JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Initialisation des extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modèle de la base de données pour l'utilisateur
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), default="user")

# Fonction d'enregistrement de l'utilisateur
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400

    # Vérification si l'utilisateur existe déjà
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User created successfully"}), 201
    except:
        db.session.rollback()
        return jsonify({"message": "Error creating user"}), 500

# Fonction de connexion de l'utilisateur
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400

    user = User.query.filter_by(username=data['username']).first()

    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({"message": "Invalid credentials"}), 401

    # Création du token d'accès JWT
    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200

# Route protégée nécessitant un token JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Récupérer l'identité de l'utilisateur à partir du token
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if user:
        return jsonify({"message": f"Hello, {user.username}!"}), 200
    return jsonify({"message": "User not found"}), 404

# Route protégée avec un contrôle d'accès basé sur les rôles
@app.route('/admin', methods=['GET'])
@jwt_required()
def admin():
    # Récupérer l'identité de l'utilisateur à partir du token
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user and user.role == 'admin':
        return jsonify({"message": "Welcome Admin!"}), 200
    return jsonify({"message": "Access denied. Admins only."}), 403

# Initialisation de la base de données
@app.before_first_request
def create_tables():
    db.create_all()

# Démarrage du serveur
if __name__ == '__main__':
    app.run(debug=True)
