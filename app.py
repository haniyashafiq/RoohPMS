from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, ConnectionFailure
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
import pandas as pd
import io
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- CONFIGURATION ---
mongo_uri = os.environ.get("MONGO_URI")
if not mongo_uri:
    print("ERROR: MONGO_URI environment variable is not set!")
else:
    print(f"MONGO_URI is configured (length: {len(mongo_uri)})")
    
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

# MongoDB client setup for serverless - lazy connection
mongo_client = None
db = None

def get_db():
    """Get database connection - creates it lazily for serverless"""
    global mongo_client, db
    
    if db is not None:
        try:
            # Test if connection is still alive
            mongo_client.admin.command('ping')
            return db
        except:
            # Connection died, reset it
            mongo_client = None
            db = None
    
    # Create new connection
    if mongo_uri:
        try:
            print("Creating MongoDB connection...")
            mongo_client = MongoClient(
                mongo_uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                socketTimeoutMS=10000,
                maxPoolSize=1,  # Important for serverless
                retryWrites=True
            )
            # Test the connection
            mongo_client.admin.command('ping')
            # Extract database name from URI or use default
            db_name = mongo_uri.split('/')[-1].split('?')[0] or 'RoohRehab'
            db = mongo_client[db_name]
            print(f"MongoDB connected to database: {db_name}")
            return db
        except Exception as e:
            print(f"MongoDB connection error: {type(e).__name__}: {e}")
            return None
    else:
        print("MONGO_URI not set")
        return None

# --- HELPER: DATABASE CHECK & INITIAL SETUP ---
def check_db():
    """Check and test database connection"""
    try:
        database = get_db()
        if database is None:
            print("Failed to get database connection")
            return False
        return True
    except Exception as e:
        print(f"Database check failed: {e}")
        return False

def ensure_initial_admin():
    """Checks for and creates the default admin users on first run."""
    if check_db():
        database = get_db()
        if database.users.count_documents({}) == 0:
            # Create Admin 1 - Mudasir
            admin1_user = {
                'username': os.environ.get('ADMIN1_USERNAME', 'mudasir'),
                'password': generate_password_hash(os.environ.get('ADMIN1_PASSWORD', 'password123')),
                'role': 'Admin',
                'name': os.environ.get('ADMIN1_NAME', 'Mudasir'),
                'email': f"{os.environ.get('ADMIN1_USERNAME', 'mudasir')}@example.com",
                'created_at': datetime.now()
            }
            database.users.insert_one(admin1_user)
            print(f"Initial Admin user '{admin1_user['username']}' created.")
            
            # Create Admin 2 - Tayyab
            admin2_user = {
                'username': os.environ.get('ADMIN2_USERNAME', 'tayyab'),
                'password': generate_password_hash(os.environ.get('ADMIN2_PASSWORD', 'password123')),
                'role': 'Admin',
                'name': os.environ.get('ADMIN2_NAME', 'Tayyab'),
                'email': f"{os.environ.get('ADMIN2_USERNAME', 'tayyab')}@example.com",
                'created_at': datetime.now()
            }
            database.users.insert_one(admin2_user)
            print(f"Initial Admin user '{admin2_user['username']}' created.")

# Run initial setup outside of request context
with app.app_context():
    ensure_initial_admin()


def normalize_email(value):
    return value.strip().lower() if isinstance(value, str) else value


def send_password_reset_email(to_email, username, token):
    """Send a password reset email using Gmail SMTP credentials."""
    gmail_user = app.config.get("GMAIL_USER")
    gmail_pass = app.config.get("GMAIL_APP_PASSWORD")

    if not gmail_user or not gmail_pass:
        print("Gmail credentials missing; cannot send password reset email.")
        return False

    base_url = url_for('index', _external=True)
    connector = '&' if '?' in base_url else '?'
    reset_link = f"{base_url}{connector}reset_token={token}"
    expires_in = app.config.get("PASSWORD_RESET_EXPIRY_MINUTES", 30)

    message = EmailMessage()
    message["Subject"] = "Reset your Rooh account password"
    message["From"] = gmail_user
    message["To"] = to_email
    message.set_content(
        f"Hello {username},\n\n"
        "We received a request to reset your password. "
        f"Use the link below to set a new password (valid for {expires_in} minutes).\n\n"
        f"{reset_link}\n\n"
        "If you did not request this, you can safely ignore this email."
    )

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(gmail_user, gmail_pass)
            server.send_message(message)
        return True
    except Exception as e:
        print(f"Failed to send reset email: {e}")
        return False


# --- AUTHENTICATION ROUTES ---

def login_required(f):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def role_required(roles):
    def decorator(f):
        @login_required
        def wrapper(*args, **kwargs):
            if not check_db():
                return jsonify({"error": "Database connection failed"}), 500
            try:
                user = get_db().users.find_one({"_id": ObjectId(session['user_id'])})
                if user and user.get('role') in roles:
                    return f(*args, **kwargs)
                return jsonify({"error": "Access Denied"}), 403
            except Exception as e:
                print(f"Role check error: {e}")
                return jsonify({"error": "Authorization error"}), 500
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

@app.route('/')
def index():
    # Frontend handles redirection to login if session is missing.
    return render_template('index.html')

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint to verify database connectivity"""
    status = {
        'status': 'ok',
        'mongo_uri_configured': bool(os.environ.get('MONGO_URI')),
        'secret_key_configured': bool(os.environ.get('SECRET_KEY')),
        'database_connected': False,
        'user_count': 0
    }
    
    try:
        if check_db():
            status['database_connected'] = True
            status['user_count'] = get_db().users.count_documents({})
        return jsonify(status), 200
    except Exception as e:
        status['error'] = str(e)
        return jsonify(status), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        # Check database connection with detailed logging
        if not check_db():
            print(f"Login failed: Database connection check failed. MONGO_URI set: {bool(os.environ.get('MONGO_URI'))}")
            return jsonify({"error": "Database connection failed. Please contact support."}), 500
        
        data = request.json
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Missing username or password"}), 400
        
        # Ensure admin exists (for serverless cold starts)
        ensure_initial_admin()
        
        user = get_db().users.find_one({"username": data['username']})
        
        if user and check_password_hash(user['password'], data['password']):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['role'] = user['role']
            return jsonify({
                "message": "Login successful",
                "username": user['username'],
                "role": user['role'],
                "name": user.get('name', user['username'])
            })
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": f"Login failed: {str(e)}"}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return jsonify({"message": "Logged out"})

@app.route('/api/auth/session', methods=['GET'])
def check_session():
    if 'user_id' in session:
        # Fetch user from database to get the name
        user = get_db().users.find_one({"_id": ObjectId(session['user_id'])})
        return jsonify({
            "is_logged_in": True,
            "username": session.get('username'),
            "role": session.get('role'),
            "name": user.get('name', session.get('username')) if user else session.get('username')
        })
    return jsonify({"is_logged_in": False})

# --- USER MANAGEMENT (ADMIN ONLY) ---
@app.route('/api/users', methods=['GET'])
@role_required(['Admin'])
def get_users():
    if not check_db(): return jsonify([])
    users_cursor = get_db().users.find({}, {'password': 0})
    users = [{**u, '_id': str(u['_id'])} for u in users_cursor]
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@role_required(['Admin'])
def create_user():
    if not check_db(): return jsonify({"error": "Database error"}), 500
    data = request.json
    if not all(k in data for k in ['username', 'password', 'role', 'name']):
        return jsonify({"error": "Missing fields"}), 400
    
    if get_db().users.find_one({"username": data['username']}):
        return jsonify({"error": "Username already exists"}), 409

    data['password'] = generate_password_hash(data['password'])
    data['created_at'] = datetime.now()
    try:
        result = get_db().users.insert_one(data)
        return jsonify({"message": "User created", "id": str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<id>', methods=['DELETE'])
@role_required(['Admin'])
def delete_user(id):
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        # Prevent deleting the logged-in user or the primary admin by ID if necessary
        get_db().users.delete_one({'_id': ObjectId(id)})
        return jsonify({"message": "User deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/change_password', methods=['POST'])
@login_required
def change_password():
    if not check_db(): return jsonify({"error": "Database error"}), 500
    data = request.json
    user_id = session['user_id']
    
    try:
        # User is changing their own password
        user = get_db().users.find_one({"_id": ObjectId(user_id)})
        if not user or not check_password_hash(user['password'], data['old_password']):
            return jsonify({"error": "Invalid old password"}), 401
        
        new_password_hash = generate_password_hash(data['new_password'])
        get_db().users.update_one({'_id': ObjectId(user_id)}, {'$set': {'password': new_password_hash}})
        return jsonify({"message": "Password updated successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- DASHBOARD METRICS ---
@app.route('/api/dashboard', methods=['GET'])
@login_required
def get_dashboard_metrics():
    if not check_db(): return jsonify({"error": "Database error"}), 500
    
    today = datetime.now()
    start_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    try:
        # 1. Total Patients
        total_patients = get_db().patients.count_documents({})

        # 2. Admissions This Month
        admissions_this_month = get_db().patients.count_documents({
            'created_at': {'$gte': start_of_month}
        })
        
        # 3. Total Income This Month (Mock: sum of Monthly Fees from active patients)
        # Assuming monthly fee is stored as 'monthlyFee' on patient record (string, e.g., "10000")
        active_patients = get_db().patients.find()
        total_income_this_month = 0
        for p in active_patients:
            try:
                fee = int(p.get('monthlyFee', '0').replace(',', ''))
                total_income_this_month += fee
            except ValueError:
                pass # Ignore invalid fees
        
        # 4. Total Canteen Sales This Month
        pipeline = [
            {'$match': {'date': {'$gte': start_of_month}}},
            {'$group': {'_id': None, 'total_sales': {'$sum': '$amount'}}}
        ]
        canteen_sales_result = list(get_db().canteen_sales.aggregate(pipeline))
        total_canteen_sales_this_month = canteen_sales_result[0]['total_sales'] if canteen_sales_result else 0
        
        return jsonify({
            'totalPatients': total_patients,
            'admissionsThisMonth': admissions_this_month,
            'totalIncomeThisMonth': total_income_this_month,
            'totalCanteenSalesThisMonth': total_canteen_sales_this_month
        })
    except Exception as e:
        print(f"DB Metric Error: {e}")
        return jsonify({"error": str(e)}), 500

# --- PATIENT API UPDATES ---

@app.route('/api/patients', methods=['GET'])
@login_required
def get_patients():
    if not check_db(): return jsonify([])
    try:
        patients_cursor = get_db().patients.find()
        patients = []
        for p in patients_cursor:
            p['_id'] = str(p['_id'])
            # Ensure monthlyFee is present for canteen view logic
            p['monthlyFee'] = p.get('monthlyFee', '0')
            patients.append(p)
        return jsonify(patients)
    except Exception as e:
        print(f"DB Fetch Error: {e}")
        return jsonify([])

@app.route('/api/patients', methods=['POST'])
@role_required(['Admin', 'Doctor']) # Only Admin/Doctor can admit
def add_patient():
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        data = request.json
        data['created_at'] = datetime.now()
        data['notes'] = [] # General Notes (Legacy)
        data['monthlyFee'] = data.get('monthlyFee', '0')
        data['monthlyAllowance'] = data.get('monthlyAllowance', '3000') # Default allowance
        result = get_db().patients.insert_one(data)
        return jsonify({"message": "Success", "id": str(result.inserted_id)}), 201
    except Exception as e:
        print(f"DB Insert Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/patients/<id>', methods=['PUT'])
@role_required(['Admin', 'Doctor'])
def update_patient(id):
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        data = request.json
        if '_id' in data: del data['_id']
        get_db().patients.update_one({'_id': ObjectId(id)}, {'$set': data})
        return jsonify({"message": "Updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/patients/<id>', methods=['DELETE'])
@role_required(['Admin'])
def delete_patient(id):
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        get_db().patients.delete_one({'_id': ObjectId(id)})
        return jsonify({"message": "Patient deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- NEW PATIENT RECORD APIS (SESSION NOTES & MEDICAL RECORDS) ---

@app.route('/api/patients/<patient_id>/session_note', methods=['POST'])
@role_required(['Admin', 'Psychologist'])
def add_session_note(patient_id):
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        data = request.json
        note = {
            'text': data['text'],
            'type': 'session_note',
            'date': datetime.now(),
            'recorded_by': session.get('username', 'System'),
            'patient_id': ObjectId(patient_id)
        }
        result = get_db().patient_records.insert_one(note)
        return jsonify({"message": "Session note added", "id": str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/patients/<patient_id>/medical_record', methods=['POST'])
@role_required(['Admin', 'Doctor'])
def add_medical_record(patient_id):
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        data = request.json
        record = {
            'title': data['title'],
            'details': data['details'],
            'type': 'medical_record',
            'date': datetime.now(),
            'recorded_by': session.get('username', 'System'),
            'patient_id': ObjectId(patient_id)
        }
        result = get_db().patient_records.insert_one(record)
        return jsonify({"message": "Medical record added", "id": str(result.inserted_id)}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        
@app.route('/api/patients/<patient_id>/records', methods=['GET'])
@login_required
def get_patient_records(patient_id):
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        records_cursor = get_db().patient_records.find({'patient_id': ObjectId(patient_id)}).sort('date', -1)
        records = []
        for r in records_cursor:
            r['_id'] = str(r['_id'])
            r['patient_id'] = str(r['patient_id'])
            r['date'] = r['date'].isoformat()
            records.append(r)
        return jsonify(records)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- CANTEEN APIS ---

@app.route('/api/canteen/sales', methods=['POST'])
@role_required(['Admin', 'Canteen'])
def record_canteen_sale():
    if not check_db(): return jsonify({"error": "Database error"}), 500
    data = request.json
    if not all(k in data for k in ['patient_id', 'amount', 'item']):
        return jsonify({"error": "Missing fields"}), 400
    
    try:
        # Convert amount to integer
        data['amount'] = int(data['amount'])
        
        sale = {
            'patient_id': ObjectId(data['patient_id']),
            'item': data['item'],
            'amount': data['amount'],
            'date': datetime.now(),
            'recorded_by': session.get('username', 'Canteen Staff')
        }
        result = get_db().canteen_sales.insert_one(sale)
        return jsonify({"message": "Sale recorded", "id": str(result.inserted_id)}), 201
    except ValueError:
        return jsonify({"error": "Amount must be a number"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/canteen/sales/breakdown', methods=['GET'])
@role_required(['Admin', 'Canteen'])
def get_canteen_breakdown():
    if not check_db(): return jsonify({"error": "Database error"}), 500
    
    today = datetime.now()
    start_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    try:
        # 1. Fetch all patients with ID, Name, and Allowance
        patients_cursor = get_db().patients.find({}, {'name': 1, 'monthlyAllowance': 1})
        patients_map = {str(p['_id']): {'name': p['name'], 'allowance': p.get('monthlyAllowance', '0'), 'sales': 0} for p in patients_cursor}
        
        # 2. Calculate monthly sales per patient
        pipeline = [
            {'$match': {'date': {'$gte': start_of_month}}},
            {'$group': {'_id': '$patient_id', 'total_sales': {'$sum': '$amount'}}}
        ]
        sales_breakdown = list(get_db().canteen_sales.aggregate(pipeline))
        
        # 3. Merge data
        for sale in sales_breakdown:
            p_id = str(sale['_id'])
            if p_id in patients_map:
                patients_map[p_id]['sales'] = sale['total_sales']
        
        # Format output
        breakdown_list = []
        for p_id, data in patients_map.items():
            try:
                sales = data['sales']
                allowance = int(data['allowance'].replace(',', ''))
                balance = allowance - sales
            except ValueError:
                sales = data['sales']
                allowance = 0
                balance = -sales
                
            breakdown_list.append({
                'id': p_id,
                'name': data['name'],
                'monthlyAllowance': data['allowance'],
                'monthlySales': sales,
                'remainingBalance': balance
            })
            
        return jsonify(breakdown_list)
    except Exception as e:
        print(f"Canteen Breakdown Error: {e}")
        return jsonify({"error": str(e)}), 500

# --- EXPORT ROUTE (No change, retained for functionality) ---

@app.route('/api/export', methods=['POST'])
@role_required(['Admin'])
def export_patients():
    if not check_db(): return jsonify({"error": "Database error"}), 500
    try:
        req_data = request.get_json() or {}
        selected_fields = req_data.get('fields', 'all')
        
        cursor = get_db().patients.find()
        patients_list = list(cursor)
        
        if not patients_list:
            return jsonify({"error": "No patients found"}), 404

        # Prepare Data (Ensure new fields are included)
        export_data = []
        for p in patients_list:
            row = {
                'name': p.get('name', ''),
                'fatherName': p.get('fatherName', ''),
                'admissionDate': p.get('admissionDate', ''),
                'idNo': p.get('idNo', ''),
                'age': p.get('age', ''),
                'cnic': p.get('cnic', ''),
                'contactNo': p.get('contactNo', ''),
                'address': p.get('address', ''),
                'complaint': p.get('complaint', ''),
                'guardianName': p.get('guardianName', ''),
                'relation': p.get('relation', ''),
                'drugProblem': p.get('drugProblem', ''),
                'maritalStatus': p.get('maritalStatus', ''),
                'prevAdmissions': p.get('prevAdmissions', ''),
                'monthlyFee': p.get('monthlyFee', ''),
                'monthlyAllowance': p.get('monthlyAllowance', ''),
                'created_at': p.get('created_at', '')
            }
            export_data.append(row)

        df = pd.DataFrame(export_data)

        if isinstance(selected_fields, list) and len(selected_fields) > 0:
            valid_fields = [f for f in selected_fields if f in df.columns]
            if valid_fields:
                df = df[valid_fields]

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Patients')
        
        output.seek(0)
        
        return send_file(
            output, 
            download_name="patients_export.xlsx", 
            as_attachment=True, 
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except ImportError:
        return jsonify({"error": "Missing 'openpyxl' library"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
