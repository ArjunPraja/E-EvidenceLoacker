from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_jwt_extended import jwt_manager, create_access_token, jwt_required, get_jwt_identity
import pymongo
import bcrypt
from PIL import Image, ImageDraw, ImageFont
import qrcode
import uuid
from io import BytesIO
import base64
from PIL import Image, ImageDraw, ImageFont
import os
from bson import ObjectId
from datetime import datetime
import re





app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'Prajapati Arjun')  # Secret key for session management

# Database Connection
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client['E_Evidence_Locker']
users_collection = db['users']
evidence_collection = db['evidence']
# admins_collection = db['admins']
global_search_collection = db['globalsearch']
checkin_collection = db['Checkin']
checkout_collection = db['Checkout']
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'Prajapati Arjun')  # Secret key for session management

# Database Connection
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client['E_Evidence_Locker']
users_collection = db['users']
evidence_collection = db['evidence']
global_search_collection = db['globalsearch']
checkin_collection = db['Checkin']
checkout_collection = db['Checkout']




@app.route('/view_evidence/<evidence_id>', methods=['GET'])
def view_evidence(evidence_id):
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    # Fetch evidence by its ObjectId
    evidence = evidence_collection.find_one({'_id': ObjectId(evidence_id)})
    
    if evidence:
        # Decode QR code and evidence image if they exist
        qr_code_image = base64.b64encode(evidence['qr_code']).decode('utf-8') if evidence.get('qr_code') else None
        evidence_image = base64.b64encode(evidence['evidence_image']).decode('utf-8') if evidence.get('evidence_image') else None
        
        return render_template('Check_In_from_FSL.html', evidence=evidence, qr_code_image=qr_code_image, evidence_image=evidence_image)
    else:
        flash('Evidence not found.', 'danger')
        return redirect(url_for('fsl_helper'))
    

# Authentication Routes
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Collect form data
        district_name = request.form.get('district_name')
        sub_district_name = request.form.get('sub_district_name')
        station_name = request.form.get('station_name')
        staff_name = request.form.get('staff_name')
        contact_no = request.form.get('contact_no')
        station_location = request.form.get('station_location')
        email = request.form.get('email')
        password = request.form.get('password')
        verify_password = request.form.get('verify_password')
        email=''.join(email.split())
        print(email)

        # Validate required fields
        if not all([district_name, sub_district_name, station_name, staff_name, contact_no, station_location, email, password, verify_password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        # Check The Email Is Government Email
        if ".gov.in" not in email:
            flash('Use Government E-Mail', 'danger')
            return redirect(url_for('register'))

        # Check if email already exists in the database
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            flash('Email already exists. Please choose a different email.', 'danger')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != verify_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        try:
            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Prepare user data for insertion
            user_data = {
                'district_name': district_name,
                'sub_district_name': sub_district_name,
                'station_name': station_name,
                'staff_name': staff_name,
                'contact_no': contact_no,
                'station_location': station_location,
                'email': email,
                'password': hashed_password,
                'uuid': str(uuid.uuid4())  # Generate and store UUID
            }

            # Insert the new user into the database
            users_collection.insert_one(user_data)
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            return redirect(url_for('register'))

    return render_template('Register.html')

@app.route('/login', methods=['POST', 'GET'])
def login_submit():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']

            # Validation: Check if all required fields are provided
            if not email or not password:
                flash('Email and password are required', 'danger')
                return redirect(url_for('login'))

            # Validation: Check if the password meets the minimum length requirement
            if len(password) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return redirect(url_for('login'))

            # Check user credentials
            user = users_collection.find_one({'email': email})
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                session['email'] = email
                session['uuid'] = user['uuid']  # Store UUID in session
                session['role'] = 'user'
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid email or password', 'danger')
        except KeyError as e:
            flash(f'Missing form field: {str(e)}', 'danger')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    # Redirect the user to the login page after logging out
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

# User Routes
@app.route('/home')
def home():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('home.html')




























@app.route('/warehousetable')
def warehousetable():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('warehousetable.html')



 

@app.route('/adddetails', methods=['GET', 'POST'])
def add_details():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form data
        case_number = request.form.get('case_number')
        inspector = request.form.get('inspector')
        crime_date = request.form.get('crime_date')
        item_name = request.form.get('item_name')
        crime_place = request.form.get('crime_place')
        evidence_type = request.form.get('evidence_type')
        storage_location = request.form.get('storage_location')
        ipc_section = request.form.get('ipc_section')
        number_plate = request.form.get('number_plate', '')

        # Handle image upload
        image_file = request.files.get('image')
        if image_file:
            img = Image.open(image_file)
            buffered = BytesIO()
            img.save(buffered, format="PNG")
            image_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
        else:
            image_str = None

        # Generate a Unique ID
        unique_id = str(uuid.uuid4())

        # Prepare data to encode in the QR code
        qr_data = f"""
        Case Number: {case_number}
        Inspector: {inspector}
        Crime Date: {crime_date}
        Item Seized: {item_name}
        Crime Place: {crime_place}
        Evidence Type: {evidence_type}
        Storage Location: {storage_location}
        IPC Section: {ipc_section}
        Number Plate: {number_plate}
        Unique ID: {unique_id}
        """

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill='black', back_color='white').convert('RGB')

        # Create a drawing context
        draw = ImageDraw.Draw(img)

        # Define the font and size for the UUID text
        try:
            font = ImageFont.truetype("arial.ttf", 24)  # Adjust font and size as needed
        except IOError:
            font = ImageFont.load_default()

        # Prepare the UUID text
        text = f"Unique ID: {unique_id}"
        
        # Calculate text size and position
        text_bbox = draw.textbbox((0, 0), text, font=font)
        text_width = text_bbox[2] - text_bbox[0]
        text_height = text_bbox[3] - text_bbox[1]
        
        # Calculate text position
        image_width, image_height = img.size
        text_x = (image_width - text_width) // 2
        text_y = image_height - text_height - 10  # 10 pixels from the bottom

        # Add the text to the image
        draw.text((text_x, text_y), text, font=font, fill='black')

        # Save QR code as an image in memory
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')

        # Save evidence data along with unique ID, QR code image (base64 encoded), and optional image
        evidence_data = {
            'username': session['email'],  # Store email in evidence data
            'case_number': case_number,
            'inspector': inspector,
            'crime_date': crime_date,
            'item_name': item_name,
            'crime_place': crime_place,
            'evidence_type': evidence_type,
            'storage_location': storage_location,
            'ipc_section': ipc_section,
            'number_plate': number_plate,
            'unique_id': unique_id,
            'qr_code': img_str,  # Storing the QR code image as base64
            'evidence_image': image_str  # Storing the uploaded image as base64
        }

        # Insert evidence data into the collection
        try:
            evidence_collection.insert_one(evidence_data)
            flash('Evidence details added successfully!', 'success')
        except Exception as e:
            flash('An error occurred while adding evidence details. Please try again.', 'danger')
            print(f"Error: {e}")
            return redirect(url_for('add_details'))

        return redirect(url_for('add_details'))

    return render_template('addDetails.html')






@app.route('/viewdetails')
def view_details():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    evidence_details = evidence_collection.find({'username': session['email']})
    return render_template('viewdetails.html', evidence_details=evidence_details)

# Check-in and Check-out Routes
@app.route('/checkin')
def checkin():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    checkin_details = checkin_collection.find({'username': session['email']})
    return render_template('CheckIn.html', checkin_details=checkin_details)

@app.route('/checkout')
def checkout():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    checkout_details = checkout_collection.find({'username': session['email']})
    return render_template('CheckOut.html', checkout_details=checkout_details)

























# Global Search
@app.route('/globalsearch', methods=['GET', 'POST'])
def global_search():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    else:
        results = evidence_collection.find()
        
        return render_template('GlobalSearch.html', result=results)
    
    return render_template('GlobalSearch.html')

@app.route('/readDetails/<evidence_id>')
def read_details1(evidence_id):
    # Find the evidence by its ID
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    else:
        evidence = evidence_collection.find_one({"_id": ObjectId(evidence_id)})
        if evidence:
           return render_template('GlobalReadDetails.html', evidence=evidence)
        else:
           return 'Evidence not found', 404
        
        

















# Court Table Routes
@app.route('/courttable')
def court_helper():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('CourtHelper.html')

@app.route('/checkin_court', methods=['GET', 'POST'])
def checkin_court():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        barcode_number = request.form['barcode_number']
        fir_number = request.form['fir_number']
        item_name = request.form['item_name']
        collected_by = request.form['collected_by']
        checkin_date = request.form['checkin_date']
        checkin_time = request.form['checkin_time']
        remarks = request.form['remarks']

        checkin_data = {
            'username': session['email'],
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkin_date': checkin_date,
            'checkin_time': checkin_time,
            'remarks': remarks
        }

        checkin_collection.insert_one(checkin_data)
        flash('Checked in successfully!', 'success')
        return redirect(url_for('checkin_court'))
    evidence=""
    return render_template('Check_In_from_Court.html',evidence=evidence)

@app.route('/checkout_court', methods=['GET', 'POST'])
def checkout_court():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        barcode_number = request.form['barcode_number']
        fir_number = request.form['fir_number']
        item_name = request.form['item_name']
        collected_by = request.form['collected_by']
        checkout_date = request.form['checkout_date']
        checkout_time = request.form['checkout_time']
        remarks = request.form['remarks']

        checkout_data = {
            'username': session['email'],
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkout_date': checkout_date,
            'checkout_time': checkout_time,
            'remarks': remarks
        }

        checkout_collection.insert_one(checkout_data)
        flash('Checked out successfully!', 'success')
        return redirect(url_for('checkout_court'))
    evidence=""
    return render_template('Check_out_from_Court.html',evidence=evidence)





















# FSL Table Routes
@app.route('/fsltable')
def fsl_helper():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('FslHelper.html')

@app.route('/checkout_fsl', methods=['GET', 'POST'])
def checkout_fsl():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        barcode_number = request.form.get('barcode_number')
        fir_number = request.form.get('fir_number')
        item_name = request.form.get('item_name')
        collected_by = request.form.get('collected_by')
        checkout_date = request.form.get('checkout_date')
        checkout_time = request.form.get('checkout_time')
        remarks = request.form.get('remarks')

        # Validate form data
        if not barcode_number or not fir_number or not item_name or not collected_by or not checkout_date or not checkout_time:
            flash('All fields are required.', 'danger')
            return redirect(url_for('checkout_fsl'))

        # try:
        #     # Ensure date and time are in correct format
        #     datetime.strptime(checkout_date, '%Y-%m-%d')  # Example format
        #     datetime.strptime(checkout_time, '%H:%M:%S')  # Example format
        # except ValueError:
        #     flash('Invalid date or time format.', 'danger')
        #     return redirect(url_for('checkout_fsl'))

        checkout_data = {
            'username': session.get('email'),
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkout_date': checkout_date,
            'checkout_time': checkout_time,
            'remarks': remarks
        }

        try:
            checkout_collection.insert_one(checkout_data)
            flash('Checked out successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred: {e}', 'danger')

        return redirect(url_for('checkout_fsl'))
    evidence=" "
    return render_template('Check_out_from_FSL.html',evidence=evidence)
@app.route('/searchoutfsl', methods=['POST'])
def searchoutfsl():
    qr_number = request.form.get('barcode_number')
    evidence = ""
    
    if qr_number:
        evidence = evidence_collection.find_one({'unique_id': qr_number})
        if evidence:
            flash('Data Collected Successfully', 'success')
        else:
            flash('No data found for the given barcode number', 'danger')
    else:
        flash('Please enter a barcode number', 'warning')
    

    return render_template('Check_out_from_FSL.html', evidence=evidence)

@app.route('/searchincourt', methods=['POST'])
def searchincourt():
    qr_number = request.form.get('barcode_number')
    evidence = None
    
    if qr_number:
        evidence = evidence_collection.find_one({'unique_id': qr_number})
        if evidence:
            flash('Data Collected Successfully', 'success')
        else:
            flash('No data found for the given barcode number', 'danger')
    else:
        flash('Please enter a barcode number', 'warning')
    
    return render_template('Check_In_from_Court.html', evidence=evidence)

@app.route('/searchoutcourt', methods=['POST'])
def searchoutcourt():
    qr_number = request.form.get('barcode_number')
    evidence = None
    
    if qr_number:
        evidence = evidence_collection.find_one({'unique_id': qr_number})
        if evidence:
            flash('Data Collected Successfully', 'success')
        else:
            flash('No data found for the given barcode number', 'danger')
    else:
        flash('Please enter a barcode number', 'warning')
    
    return render_template('Check_out_from_Court.html', evidence=evidence)





@app.route('/searchinfsl', methods=['POST'])
def searchinfsl():
    qr_number = request.form.get('barcode_number')
    evidence = None

    if not qr_number:
        flash('Please enter a barcode number', 'warning')
        return redirect(url_for('checkin_fsl'))

    # Simple validation for barcode format
    if not re.match(r'^[A-Za-z0-9_-]+$', qr_number):
        flash('Invalid barcode format', 'danger')
        return redirect(url_for('checkin_fsl'))

    # Fetch evidence data from MongoDB
    evidence = evidence_collection.find_one({'unique_id': qr_number})
    
    if evidence:
        flash('Data Collected Successfully', 'success')
    else:
        flash('No data found for the given barcode number', 'danger')

    return render_template('Check_In_from_FSL.html', evidence=evidence)

@app.route('/checkin_fsl', methods=['GET', 'POST'])
def checkin_fsl():
    if 'email' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Fetching and validating input data
        barcode_number = request.form.get('barcode_number')
        fir_number = request.form.get('fir_number')
        item_name = request.form.get('item_name')
        collected_by = request.form.get('collected_by')
        checkin_date = request.form.get('checkin_date')
        checkin_time = request.form.get('checkin_time')
        remarks = request.form.get('remarks', '')  # Remarks are optional

        # Input validation
        if not all([barcode_number, fir_number, item_name, collected_by, checkin_date, checkin_time]):
            flash('All fields except remarks are required.', 'warning')
            return redirect(url_for('checkin_fsl'))

        # Ensure date and time are in proper format
        try:
            datetime.strptime(checkin_date, '%Y-%m-%d')
            datetime.strptime(checkin_time, '%H:%M')
        except ValueError:
            flash('Invalid date or time format', 'danger')
            return redirect(url_for('checkin_fsl'))

        # Prepare data for insertion
        checkin_data = {
            'username': session['email'],
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkin_date': checkin_date,
            'checkin_time': checkin_time,
            'remarks': remarks
        }

        # Insert data into MongoDB
        try:
            checkin_collection.insert_one(checkin_data)
            flash('Checked in successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred while checking in: {str(e)}', 'danger')

        return redirect(url_for('checkin_fsl'))
    evidence=""
    return render_template('Check_In_from_FSL.html',evidence=evidence)

# Under Construction Route
@app.route('/underconstruction')
def under_construction():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('underConstruction.html')

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
