from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///fitness_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(200))

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    challenge_type = db.Column(db.String(20))  # 'daily', 'team', 'sponsored'
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)

class UserChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    progress = db.Column(db.Float, default=0)

class Workout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50))
    duration = db.Column(db.Integer)
    calories_burned = db.Column(db.Integer)

# Helper function to check for missing JSON fields
def check_json_fields(data, required_fields):
    missing = [field for field in required_fields if field not in data]
    if missing:
        return jsonify({"message": f"Missing {', '.join(missing)}"}), 400
    return None

# Routes
@app.route('/')
def home():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    missing_fields = check_json_fields(data, ["username", "email", "password"])
    if missing_fields:
        return missing_fields

    try:
        hashed_password = generate_password_hash(data['password'])
        new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "Username or email already exists"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

    return jsonify({"message": "User created successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()

    missing_fields = check_json_fields(data, ["username", "password"])
    if missing_fields:
        return missing_fields

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    # Fetch and return dashboard data
    return jsonify({"message": "Dashboard data"}), 200

@app.route('/challenges', methods=['GET'])
@jwt_required()
def get_challenges():
    challenges = Challenge.query.all()
    return jsonify([{"id": c.id, "title": c.title, "description": c.description, "type": c.challenge_type} for c in challenges]), 200

@app.route('/challenges/<int:challenge_id>/join', methods=['POST'])
@jwt_required()
def join_challenge(challenge_id):
    current_user_id = get_jwt_identity()
    challenge = Challenge.query.get(challenge_id)
    if not challenge:
        return jsonify({"message": "Challenge not found"}), 404

    user_challenge = UserChallenge.query.filter_by(user_id=current_user_id, challenge_id=challenge_id).first()
    if user_challenge:
        return jsonify({"message": "User already joined this challenge"}), 400

    new_user_challenge = UserChallenge(user_id=current_user_id, challenge_id=challenge_id)
    db.session.add(new_user_challenge)
    db.session.commit()
    return jsonify({"message": "Joined challenge successfully"}), 201

@app.route('/workouts', methods=['POST'])
@jwt_required()
def log_workout():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    missing_fields = check_json_fields(data, ["type", "duration", "calories_burned"])
    if missing_fields:
        return missing_fields

    new_workout = Workout(user_id=current_user_id, type=data['type'], duration=data['duration'], calories_burned=data['calories_burned'])
    db.session.add(new_workout)
    db.session.commit()
    return jsonify({"message": "Workout logged successfully"}), 201

@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if request.method == 'GET':
        return jsonify({"username": user.username, "email": user.email, "avatar": user.avatar}), 200
    elif request.method == 'PUT':
        data = request.get_json()
        user.username = data.get('username', user.username)
        user.email = data.get('email', user.email)
        user.avatar = data.get('avatar', user.avatar)
        db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)