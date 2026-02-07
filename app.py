from flask import Flask, request, render_template, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from werkzeug.security import generate_password_hash, check_password_hash
import tensorflow as tf
import numpy as np
from PIL import Image
import io
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blood_cancer.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Load the TensorFlow Lite model
model_path = "model1 (MobileNetV2).tflite"
interpreter = tf.lite.Interpreter(model_path=model_path)
interpreter.allocate_tensors()

# Get input and output details
input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()

def preprocess_image(image):
    """Preprocess image for model prediction"""
    image = image.resize((224, 224))
    if image.mode != 'RGB':
        image = image.convert('RGB')
    image_array = np.array(image, dtype=np.float32)
    image_array = image_array / 255.0
    image_array = np.expand_dims(image_array, axis=0)
    return image_array

def predict_disease(image_array):
    """Make prediction using the loaded model"""
    interpreter.set_tensor(input_details[0]['index'], image_array)
    interpreter.invoke()
    output = interpreter.get_tensor(output_details[0]['index'])
    return output

# Database Models
class User(UserMixin, db.Model):
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    full_name = StringField('Full Name', validators=[DataRequired()])
    phone = StringField('Phone Number')
    role = SelectField('Role', choices=[('patient', 'Patient'), ('doctor', 'Doctor'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class MessageForm(FlaskForm):
    recipient_id = SelectField('Recipient', coerce=int, validators=[DataRequired()])
    subject = StringField('Subject', validators=[DataRequired()])
    content = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Message')

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'patient':
            return redirect(url_for('patient_dashboard'))
        elif current_user.role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role=form.role.data,
            full_name=form.full_name.data,
            phone=form.phone.data
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    if current_user.role != 'patient':
        return redirect(url_for('home'))
    predictions = Prediction.query.filter_by(user_id=current_user.id).order_by(Prediction.created_at.desc()).limit(10).all()
    messages = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.sent_at.desc()).all()
    return render_template('patient_dashboard.html', predictions=predictions, messages=messages)

@app.route('/predict', methods=['POST'])
@login_required
def predict():
    if current_user.role != 'patient':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image uploaded'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No image selected'}), 400
        
        image = Image.open(io.BytesIO(file.read()))
        processed_image = preprocess_image(image)
        prediction = predict_disease(processed_image)
        
        confidence = float(np.max(prediction))
        predicted_class = np.argmax(prediction)
        
        class_mapping = {
            0: {
                "stage": "Early Pre-B",
                "severity": "Early Stage",
                "description": "Early stage malignant cells detected - 'about to grow'",
                "status": "YES",
                "result": "Disease Present (Early Stage)"
            },
            1: {
                "stage": "Pre-B", 
                "severity": "Developing Stage",
                "description": "Developing malignant cells detected",
                "status": "YES",
                "result": "Disease Present (Developing Stage)"
            },
            2: {
                "stage": "Pro-B",
                "severity": "Advanced Stage", 
                "description": "Advanced malignant cells detected",
                "status": "YES",
                "result": "Disease Present (Advanced Stage)"
            },
            3: {
                "stage": "Benign",
                "severity": "Normal",
                "description": "Healthy blood cells - no disease detected",
                "status": "NO", 
                "result": "Disease Absent (Healthy)"
            }
        }
        
        prediction_info = class_mapping[predicted_class]
        
        # Save prediction to database
        db_prediction = Prediction(
            user_id=current_user.id,
            prediction=prediction_info['result'],
            status=prediction_info['status'],
            stage=prediction_info['stage'],
            severity=prediction_info['severity'],
            description=prediction_info['description'],
            confidence=confidence
        )
        db.session.add(db_prediction)
        db.session.commit()
        
        return jsonify({
            'prediction': prediction_info['result'],
            'status': prediction_info['status'],
            'stage': prediction_info['stage'],
            'severity': prediction_info['severity'],
            'description': prediction_info['description'],
            'confidence': f"{confidence:.2%}",
            'raw_prediction': prediction.tolist()
        })
        
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        return redirect(url_for('home'))
    
    patients = User.query.filter_by(role='patient').all()
    recent_predictions = Prediction.query.order_by(Prediction.created_at.desc()).limit(50).all()
    
    patient_data = []
    for patient in patients:
        latest_prediction = Prediction.query.filter_by(user_id=patient.id).order_by(Prediction.created_at.desc()).first()
        patient_data.append({
            'patient': patient,
            'latest_prediction': latest_prediction
        })
    
    form = MessageForm()
    form.recipient_id.choices = [(p.id, p.full_name) for p in patients]
    
    return render_template('doctor_dashboard.html', patient_data=patient_data, form=form, recent_predictions=recent_predictions)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    
    patients = User.query.filter_by(role='patient').all()
    doctors = User.query.filter_by(role='doctor').all()
    admins = User.query.filter_by(role='admin').all()
    all_users = User.query.all()
    
    return render_template('admin_dashboard.html', patients=patients, doctors=doctors, admins=admins, all_users=all_users)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    if current_user.role != 'doctor':
        return redirect(url_for('home'))
    
    form = MessageForm()
    form.recipient_id.choices = [(p.id, p.full_name) for p in User.query.filter_by(role='patient').all()]
    
    if form.validate_on_submit():
        message = Message(
            sender_id=current_user.id,
            recipient_id=form.recipient_id.data,
            subject=form.subject.data,
            content=form.content.data
        )
        db.session.add(message)
        db.session.commit()
        flash('Message sent successfully!', 'success')
        return redirect(url_for('doctor_dashboard'))
    
    return redirect(url_for('doctor_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
