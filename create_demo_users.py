from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from datetime import datetime

# Create Flask app instance (same as app.py)
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blood_cancer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Import models from app.py (you may need to adjust imports)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'patient', 'doctor', 'admin'
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    predictions = db.relationship('Prediction', backref='user', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy=True)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    prediction = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(10), nullable=False)  # 'YES' or 'NO'
    stage = db.Column(db.String(50))
    severity = db.Column(db.String(50))
    description = db.Column(db.Text)
    confidence = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

def create_demo_users():
    with app.app_context():
        # Create all tables
        db.create_all()

        # Demo users data
        demo_users = [
            {
                'username': 'patient1',
                'email': 'patient1@example.com',
                'password': '123',
                'role': 'patient',
                'full_name': 'Patient One',
                'phone': '123-456-7890'
            },
            {
                'username': 'patient2',
                'email': 'patient2@example.com',
                'password': '123',
                'role': 'patient',
                'full_name': 'Patient Two',
                'phone': '123-456-7891'
            },
            {
                'username': 'patient3',
                'email': 'patient3@example.com',
                'password': '123',
                'role': 'patient',
                'full_name': 'Patient Three',
                'phone': '123-456-7892'
            },
            {
                'username': 'doctor',
                'email': 'doctor@example.com',
                'password': '123',
                'role': 'doctor',
                'full_name': 'Dr. Medical Expert',
                'phone': '123-456-7893'
            },
            {
                'username': 'admin',
                'email': 'admin@example.com',
                'password': '123',
                'role': 'admin',
                'full_name': 'System Administrator',
                'phone': '123-456-7894'
            }
        ]

        for user_data in demo_users:
            # Check if user already exists
            existing_user = User.query.filter_by(username=user_data['username']).first()
            if existing_user:
                print(f"User {user_data['username']} already exists, skipping...")
                continue

            # Create new user
            hashed_password = generate_password_hash(user_data['password'])
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                password_hash=hashed_password,
                role=user_data['role'],
                full_name=user_data['full_name'],
                phone=user_data['phone']
            )
            db.session.add(user)
            print(f"Created user: {user_data['username']} ({user_data['role']})")

        # Commit all changes
        db.session.commit()
        print("All demo users created successfully!")

if __name__ == '__main__':
    create_demo_users()
