from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from datetime import datetime

# Create Flask app instance
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blood_cancer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Import models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def test_login():
    with app.app_context():
        # Test login with email (since the form uses email field)
        test_credentials = [
            ('patient1@example.com', '123'),
            ('patient2@example.com', '123'), 
            ('patient3@example.com', '123'),
            ('doctor@example.com', '123'),
            ('admin@example.com', '123')
        ]
        
        for email, password in test_credentials:
            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password_hash, password):
                    print(f"✅ Login successful for {email} - Role: {user.role}")
                else:
                    print(f"❌ Password incorrect for {email}")
            else:
                print(f"❌ User not found for {email}")

if __name__ == '__main__':
    test_login()
