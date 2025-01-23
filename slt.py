from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import jwt
import bcrypt

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///smart_loan_tracker.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Loan model
class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    loan_type = db.Column(db.String(50), nullable=False)
    principal = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    tenure_months = db.Column(db.Integer, nullable=False)
    emi = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=False)

# Utility function to calculate EMI
def calculate_emi(principal, interest_rate, tenure_months):
    monthly_rate = interest_rate / (12 * 100)
    emi = (principal * monthly_rate * ((1 + monthly_rate) ** tenure_months)) / (((1 + monthly_rate) ** tenure_months) - 1)
    return round(emi, 2)

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    new_user = User(username=data['username'], password=hashed_pw.decode('utf-8'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"})

# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.utcnow() + timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({"token": token})
    return jsonify({"message": "Invalid credentials!"}), 401

# Add a loan
@app.route('/add-loan', methods=['POST'])
def add_loan():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token is missing!"}), 401
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
    except:
        return jsonify({"message": "Invalid token!"}), 401

    data = request.json
    emi = calculate_emi(data['principal'], data['interest_rate'], data['tenure_months'])
    due_date = datetime.strptime(data['due_date'], "%Y-%m-%d")
    new_loan = Loan(user_id=user_id, loan_type=data['loan_type'], principal=data['principal'], 
                    interest_rate=data['interest_rate'], tenure_months=data['tenure_months'], emi=emi, due_date=due_date)
    db.session.add(new_loan)
    db.session.commit()
    return jsonify({"message": "Loan added successfully!", "emi": emi})

# Get all loans for the user
@app.route('/loans', methods=['GET'])
def get_loans():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token is missing!"}), 401
    try:
        decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = decoded_token['user_id']
    except:
        return jsonify({"message": "Invalid token!"}), 401

    loans = Loan.query.filter_by(user_id=user_id).all()
    loan_list = [
        {
            "loan_type": loan.loan_type,
            "principal": loan.principal,
            "interest_rate": loan.interest_rate,
            "tenure_months": loan.tenure_months,
            "emi": loan.emi,
            "due_date": loan.due_date.strftime("%Y-%m-%d")
        }
        for loan in loans
    ]
    return jsonify(loan_list)

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
