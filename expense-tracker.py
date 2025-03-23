from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from flask_bcrypt import Bcrypt
from datetime import datetime
from flask_swagger_ui import get_swaggerui_blueprint

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this in production

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

### swagger specific ###
SWAGGER_URL = '/swagger'
API_URL = 'https://expense-tracker-9w88.onrender.com/static/swagger.json'  # Use HTTPS
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Expense Tracker API"
    }
)
app.register_blueprint(swaggerui_blueprint)
### end swagger specific ###

# ----------------------- MODELS -------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)  # "income" or "expense"
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# ----------------------- AUTHENTICATION -------------------------

@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Welcome to the Expense Tracker API'})

@app.route('/auth/register', methods=['OPTIONS'])
def preflight_register():
    return '', 204

@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        new_user = User(name=data['name'], email=data['email'], password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        print(f"Error during registration: {e}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({'token': access_token})
    return jsonify({'error': 'Invalid credentials'}), 401

# ----------------------- TRANSACTIONS -------------------------

@app.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'id': t.id, 'amount': t.amount, 'type': t.type, 'category': t.category, 'date': str(t.date)
    } for t in transactions])

@app.route('/transactions', methods=['POST'])
@jwt_required()
def add_transaction():
    user_id = get_jwt_identity()
    data = request.json
    new_transaction = Transaction(
        user_id=user_id, amount=data['amount'], type=data['type'], category=data['category'], date=datetime.strptime(data['date'], '%Y-%m-%d')
    )
    db.session.add(new_transaction)
    db.session.commit()
    return jsonify({'message': 'Transaction added successfully'}), 201

@app.route('/transactions/<int:id>', methods=['PUT'])
@jwt_required()
def update_transaction(id):
    user_id = get_jwt_identity()
    transaction = Transaction.query.filter_by(id=id, user_id=user_id).first()
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404

    data = request.json
    if 'amount' in data:
        transaction.amount = data['amount']
    if 'type' in data:
        transaction.type = data['type']
    if 'category' in data:
        transaction.category = data['category']
    db.session.commit()
    return jsonify({'message': 'Transaction updated successfully'})

@app.route('/transactions/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_transaction(id):
    user_id = get_jwt_identity()
    transaction = Transaction.query.filter_by(id=id, user_id=user_id).first()
    if not transaction:
        return jsonify({'error': 'Transaction not found'}), 404
    db.session.delete(transaction)
    db.session.commit()
    return jsonify({'message': 'Transaction deleted successfully'})

# ----------------------- CATEGORIES -------------------------

@app.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    categories = Category.query.all()
    return jsonify([{'id': c.id, 'name': c.name} for c in categories])

@app.route('/categories', methods=['POST'])
@jwt_required()
def add_category():
    data = request.json
    new_category = Category(name=data['name'])
    db.session.add(new_category)
    db.session.commit()
    return jsonify({'message': 'Category added successfully'}), 201

# ----------------------- REPORTS -------------------------

@app.route('/reports/monthly', methods=['GET'])
@jwt_required()
def get_monthly_report():
    month = request.args.get('month')
    if not month:
        return jsonify({'error': 'Month parameter is required'}), 400

    try:
        year, month = map(int, month.split('-'))
        start_date = datetime(year, month, 1).date()
        end_date = datetime(year, month + 1, 1).date() if month < 12 else datetime(year + 1, 1, 1).date()
    except ValueError:
        return jsonify({'error': 'Invalid month format. Use YYYY-MM'}), 400

    user_id = get_jwt_identity()
    transactions = Transaction.query.filter(
        Transaction.user_id == user_id,
        Transaction.date >= start_date,
        Transaction.date < end_date
    ).all()

    report = {
        'income': sum(t.amount for t in transactions if t.type == 'income'),
        'expense': sum(t.amount for t in transactions if t.type == 'expense')
    }

    return jsonify(report)

# ----------------------- DATABASE INITIALIZATION -------------------------

@app.before_request
def create_tables():
    db.create_all()
    if not Category.query.first():  # Seed initial categories
        db.session.add_all([Category(name="Salary"), Category(name="Groceries"), Category(name="Bills"), Category(name="Entertainment")])
        db.session.commit()

# ----------------------- RUN SERVER -------------------------

if __name__ == '__main__':
    app.run(debug=True)
