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

def check_demo_users():
    with app.app_context():
        # Check all users in database
        users = User.query.all()
        print(f"Total users in database: {len(users)}")
        
        for user in users:
            print(f"Username: {user.username}, Email: {user.email}, Role: {user.role}")
        
        # Check specific demo users
        demo_usernames = ['patient1', 'patient2', 'patient3', 'doctor', 'admin']
        
        for username in demo_usernames:
            user = User.query.filter_by(username=username).first()
            if user:
                print(f"✅ {username} exists - Role: {user.role}")
                # Test password
                if check_password_hash(user.password_hash, '123'):
                    print(f"   ✅ Password '123' is correct")
                else:
                    print(f"   ❌ Password '123' is incorrect")
            else:
                print(f"❌ {username} does not exist")

if __name__ == '__main__':
    check_demo_users()
