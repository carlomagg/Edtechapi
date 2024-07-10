import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Configure the SQLAlchemy part of the app instance
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Setup the Flask-JWT-Extended extension with the provided secret key
app.config['JWT_SECRET_KEY'] = 'UPpok5mOKopDAYyp00EQ7OK8LbI6b4aW'
jwt = JWTManager(app)

# Create the SQLAlchemy db instance
db = SQLAlchemy(app)

# Define a User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data:
            raise ValueError("No JSON data received")
    except Exception as e:
        app.logger.error(f"Failed to decode JSON object: {e}")
        return jsonify({'message': 'Failed to decode JSON object', 'error': str(e)}), 400

    app.logger.debug(f"Received data: {data}")

    fullname = data.get('fullname')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not fullname or not email or not password or not confirm_password:
        return jsonify({'message': 'All fields are required'}), 400

    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 400

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

    new_user = User(fullname=fullname, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            raise ValueError("No JSON data received")
    except Exception as e:
        app.logger.error(f"Failed to decode JSON object: {e}")
        return jsonify({'message': 'Failed to decode JSON object', 'error': str(e)}), 400

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity={'email': user.email})
    return jsonify({'access_token': access_token}), 200

# Protected route example
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'logged_in_as': current_user}), 200

if __name__ == '__main__':
    app.run(debug=True)
