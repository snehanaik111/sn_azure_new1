from flask import Flask, request, make_response,send_file, render_template, redirect, session, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import logging
import json
import qrcode  # Import QR code library
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from sqlalchemy import LargeBinary
import sqlite3

from flask import send_file
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'

# Define conversion table
conversion_table = {
    240: 8.875,
    234: 8.625,
    228: 8.375,
    222: 8.125,
    215: 7.875,
    209: 7.625,
    203: 7.375,
    197: 7.125,
    196: 7.125,
    190: 6.875,
    183: 6.625,
    177: 6.375,
    170: 6.125,
    164: 5.875,
    158: 5.625,
    151: 5.375,
    152: 5.375,
    144: 5.125,
    138: 4.875,
    131: 4.625,
    125: 4.375,
    118: 4.125,
    111: 3.875,
    105: 3.625,
    98: 3.375,
    91: 3.125,
    85: 2.875,
    78: 2.625,
    71: 2.375,
    70: 2.225,
    64: 2.125,
    57: 1.875,
    50: 1.625,
    51: 1.625,
    42: 1.375,
    35: 1.125,
    28: 0.875,
    21: 0.625,
    19: 0.696,
    14: 0.375,
    6: 0.125,
    0: 0,
    "Sensor Dead Band": 0,
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Integer)

    def __init__(self, email, password, name, is_admin):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.is_admin = is_admin       
    
    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

class LevelSensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date = db.Column(db.String(50))
    full_addr = db.Column(db.Integer)
    sensor_data = db.Column(db.Float)
    vehicleno = db.Column(db.String(50))
    volume_liters = db.Column(db.Float)  # New column for converted volumes
    qrcode = db.Column(LargeBinary)
    pdf = db.Column(LargeBinary)
   
    def __init__(self, date, full_addr, sensor_data, vehicleno, volume_liters):
        self.date = date
        self.full_addr = full_addr
        self.sensor_data = sensor_data
        self.vehicleno = vehicleno
        self.volume_liters = volume_liters
        self.qrcode = self.generate_qr_code(self.vehicleno)
        self.pdf = self.generate_pdf()


    def generate_qr_code(self, id):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=4,
            border=4,
        )
        url = url_for('generate_pdf', id=id, _external=True)
        qr.add_data(url)
        qr.make(fit=True)

        img = qr.make_image(fill='black', back_color='white')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()

    def generate_pdf(self):
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.drawString(100, 750, f"Date: {self.date}")
        c.drawString(100, 730, f"Full Address: {self.full_addr}")
        c.drawString(100, 710, f"Sensor Data: {self.sensor_data}")
        c.drawString(100, 690, f"vehicleno: {self.vehicleno}")
        c.drawString(100, 670, f"Volume (liters): {self.volume_liters}")
        c.showPage()
        c.save()

        buffer.seek(0)
        return buffer.getvalue()
    
    def __repr__(self):
        return (f"<LevelSensorData(date='{self.date}', full_addr='{self.full_addr}', "
                f"sensor_data={self.sensor_data}, vehicleno='{self.vehicleno}', "
                f"volume_liters={self.volume_liters})>")

def create_admin_user():
    admin_email = 'admin@gmail.com'
    admin_password = 'admin'
    admin_name = 'Admin'
    
    existing_admin = User.query.filter_by(email=admin_email).first()
    if not existing_admin:
        admin_user = User(email=admin_email, password=admin_password, name=admin_name, is_admin=1)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created")

with app.app_context():
    db.create_all()
    create_admin_user()  # Call the function to create the admin user
    

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        is_admin = request.form['is_admin']

        new_user = User(name=name, email=email, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')

    return render_template('signup.html')

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('is_admin')

    if not name or not email or not password:
        return jsonify({"message": "Please provide name, email, isAdmin and password"}), 400

    try:
        if User.query.filter_by(email=email).first():
            return jsonify({"message": "Email already registered"}), 400

        new_user = User(name=name, email=email, password=password,is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            if user.is_admin == 1:
                return redirect('/dashboard')
            elif user.is_admin == 0:
                return redirect('/dashboard')
        else:
            error = 'Please provide correct credentials to login.'

    return render_template('login.html', error=error)

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    email = data['email']
    password = data['password']
    is_admin = data['is_admin']

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = user.email
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        filter_option = request.args.get('filter', 'latest')
        page = request.args.get('page', 1, type=int)
        search_query = request.args.get('query')

        if search_query:
            sense_data_pagination = LevelSensorData.query.filter(
                (LevelSensorData.date.like(f'%{search_query}%')) |
                (LevelSensorData.full_addr.like(f'%{search_query}%')) |
                (LevelSensorData.sensor_data.like(f'%{search_query}%')) |
                (LevelSensorData.imei.like(f'%{search_query}%'))
            ).order_by(LevelSensorData.date.desc()).paginate(page=page, per_page=10)
        else:
            if filter_option == 'oldest':
                sense_data_pagination = LevelSensorData.query.order_by(LevelSensorData.date.asc()).paginate(page=page, per_page=10)
            else:
                sense_data_pagination = LevelSensorData.query.order_by(LevelSensorData.date.desc()).paginate(page=page, per_page=10)

        sense_data = sense_data_pagination.items
        for data_point in sense_data:
            data_point.volume_liters = get_volume(data_point.sensor_data)

        return render_template(
            'dashboard.html',
            user=user,
            sense_data=sense_data,
            filter_option=filter_option,
            pagination=sense_data_pagination,
        )
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect('/login')

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop('email', None)
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/user/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": "User deleted successfully"}), 200
    else:
        return jsonify({"message": "User not found"}), 404

logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

api_logger = logging.getLogger('api_logger')
api_handler = logging.FileHandler('apilog.txt')
api_handler.setLevel(logging.INFO)
api_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
api_logger.addHandler(api_handler)


@app.route('/level_sensor_data', methods=['POST'])
def receive_level_sensor_data():
    if request.method == 'POST':
        try:
            if not request.is_json:
                api_logger.error("Request content type is not JSON")
                return jsonify({'status': 'failure', 'message': 'Request content type is not JSON'}), 400
            request_data = request.get_json()
            modbus_test_data = request_data.get('level_sensor_data', '{}')
            try:
                sense_data = json.loads(modbus_test_data)
            except json.JSONDecodeError:
                api_logger.error("Invalid JSON format in modbus_TEST")
                return jsonify({'status': 'failure', 'message': 'Invalid JSON format in modbus_TEST'}), 400

            api_logger.info("API called with data: %s", sense_data)

            # Extracting data from JSON
            date = sense_data.get('D', '')
            full_addr = sense_data.get('address', 0)
            sensor_data = sense_data.get('data', [])
            vehicleno = sense_data.get('Vehicle no', '')

            if not all([date, full_addr, sensor_data, vehicleno]):
                api_logger.error("Missing required data fields")
                return jsonify({'status': 'failure', 'message': 'Missing required data fields'}), 400

            # Ensure sensor_data is a list and extract the first element
            if isinstance(sensor_data, list) and sensor_data:
                sensor_data = sensor_data[0]
            else:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Convert sensor_data to float
            try:
                sensor_data = float(sensor_data)
            except ValueError:
                api_logger.error("Invalid sensor data format")
                return jsonify({'status': 'failure', 'message': 'Invalid sensor data format'}), 400

            # Fetch volume from conversion table
            volume_liters = get_volume(sensor_data)
            if volume_liters is None:
                api_logger.error("Failed to convert sensor data to volume")
                return jsonify({'status': 'failure', 'message': 'Failed to convert sensor data to volume'}), 400

            # Create a new LevelSensorData object with volume_liters and add it to the database
            new_data = LevelSensorData(date=date, full_addr=full_addr, sensor_data=sensor_data, vehicleno=vehicleno, volume_liters=volume_liters)
            db.session.add(new_data)
            db.session.commit()

            # Log success
            api_logger.info("Data stored successfully: %s", json.dumps(sense_data))

            # Return a response
            response = {'status': 'success', 'message': 'Data received and stored successfully'}
            return jsonify(response), 200

        except Exception as e:
            # Log failure
            api_logger.error("Failed to store data: %s", e)
            return jsonify({'status': 'failure', 'message': 'Failed to store data'}), 500

    api_logger.info("Received non-POST request at /level_sensor_data, redirecting to /dashboard")
    return redirect('/dashboard')


@app.route('/api/device_entries_logged', methods=['GET'])
def api_device_entries_logged():
    if 'email' in session:
        count = LevelSensorData.query.count()
        return jsonify({"device_entries_logged": count}), 200
    return jsonify({"message": "Unauthorized"}), 401

@app.route('/api/no_of_devices_active', methods=['GET'])
def api_no_of_devices_active():
    if 'email' in session:
        active_devices = db.session.query(db.func.count(db.distinct(LevelSensorData.vehicleno))).scalar()
        return jsonify({"no_of_devices_active": active_devices}), 200
    return jsonify({"message": "Unauthorized"}), 401

@app.route('/search', methods=['GET'])
def search_sensor_data():
    query = request.args.get('query')
    page = request.args.get('page', 1, type=int)

    if query:
        sense_data_pagination = LevelSensorData.query.filter(
            (LevelSensorData.date.like(f'%{query}%')) |
            (LevelSensorData.full_addr.like(f'%{query}%')) |
            (LevelSensorData.sensor_data.like(f'%{query}%')) |
            (LevelSensorData.vehicleno.like(f'%{query}%'))
        ).paginate(page=page, per_page=10)
        sense_data = sense_data_pagination.items
    else:
        sense_data_pagination = LevelSensorData.query.paginate(page=page, per_page=10)
        sense_data = sense_data_pagination.items

    user = User.query.filter_by(email=session.get('email')).first()

    return render_template('dashboard.html', user=user, sense_data=sense_data, pagination=sense_data_pagination)

# Fetch the volume from the conversion table
def get_volume(sensor_data):
    if sensor_data in conversion_table:
        return conversion_table[sensor_data]
    else:
        numeric_keys = [key for key in conversion_table if isinstance(key, int)]
        lower_key = max(key for key in numeric_keys if key <= sensor_data)
        upper_keys = [key for key in numeric_keys if key > sensor_data]
        if upper_keys:
            upper_key = min(upper_keys)
            return interpolate(lower_key, conversion_table[lower_key], upper_key, conversion_table[upper_key], sensor_data)
        return None

def interpolate(x1, y1, x2, y2, x):
    return round(y1 + ((y2 - y1) / (x2 - x1)) * (x - x1), 3)


@app.route('/api/sensor_data')
def get_sensor_data():
    try:
        sensor_data = LevelSensorData.query.all()
        if not sensor_data:
            return jsonify(error='No data available'), 404
        

        labels = [str(data.date) for data in sensor_data]
        sensor_values = [data.sensor_data for data in sensor_data]
        volume_liters = [data.volume_liters for data in sensor_data]
        
        return jsonify(labels=labels, sensorData=sensor_values, volumeLiters=volume_liters)
    except Exception as e:
        print(f"Error fetching sensor data: {str(e)}")
        return jsonify(error='Internal server error'), 500
    
    #qr and pdf
@app.route('/generate_pdf/<int:id>', methods=['GET'])
def generate_pdf(id):
    record = LevelSensorData.query.get_or_404(id)
    return send_file(
        io.BytesIO(record.pdf),
        as_attachment=True,
        download_name=f"record_{id}.pdf",
        mimetype='application/pdf'
    )
 
import json
# Modify the generate_qr function to encode the URL of the PDF route
@app.route('/generate_qr/<int:id>')
def generate_qr(id):
    record = LevelSensorData.query.get_or_404(id)
    pdf_url = url_for('generate_pdf', id=id, _external=True)  # Generate PDF route URL
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=4,
        border=4,
    )
    qr.add_data(pdf_url)  # Encode PDF URL in the QR code
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img_io = io.BytesIO()
    img.save(img_io, format='PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')  

# Create a route to handle redirection from QR code to PDF
@app.route('/scan_qr/<vehicleno>', methods=['GET'])
def scan_qr(vehicleno):
    record = LevelSensorData.query.filter_by(vehicleno=vehicleno).first_or_404()
    return redirect(url_for('generate_pdf', id=record.id))






#to update sensor table

def get_new_data(last_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sensors WHERE id > ?", (last_id,))
    new_data = cursor.fetchall()
    conn.close()
    return new_data

@app.route('/fetch_new_data', methods=['GET'])
def fetch_new_data():
    last_id = int(request.args.get('last_id', 0))
    new_data = get_new_data(last_id)
    return jsonify(new_data)





if __name__ == '__main__':
    
    app.run(debug=True)