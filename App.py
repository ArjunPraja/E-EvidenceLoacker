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
import uuid
import qrcode
from io import BytesIO
from PIL import Image
import base64
# Create a Flask application






app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'Prajapati Arjun')  # Secret key for session management

# Database Connection
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client['E_Evidence_Locker']
users_collection = db['users']
evidence_collection = db['evidence']
admins_collection = db['admins']
global_search_collection = db['globalsearch']
checkin_collection = db['Checkin']
checkout_collection = db['Checkout']

# Authentication Routes
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST', 'GET'])
def login_submit():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

         # Validation: Check if all required fields are provided
        if not username or not password:
            flash('Username and password are required', 'danger')
            return redirect(url_for('login_submit'))
        
        # Validation: Check if the password meets the minimum length requirement
        if len(username) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('login_submit'))
        
        # Validation: Check if the password meets the minimum length requirement
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return redirect(url_for('login_submit'))

        
        admin = admins_collection.find_one({'username': username})
        if admin and bcrypt.checkpw(password.encode('utf-8'), admin['password']):
            session['username'] = username
            session['role'] = 'admin'
            flash('Login successful!', 'success')
            return redirect(url_for('admin'))

        user = users_collection.find_one({'username': username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['username'] = username
            session['role'] = 'user'
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

 
@app.route('/logout')
def logout():
    # Clear the session
    session.clear()
    # Redirect the user to the login page or homepage after logging out
    flash("Logout SuccessFully","success")
    return redirect(url_for('login')) 

































# Admin Routes
@app.route('/admin')
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Access Denied', 'danger')
        return redirect(url_for('login'))
    return render_template('adminHome.html')




@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        sub_district_name = request.form['sub_district_name']
        registrant_name = request.form['registrant_name']
        station_name = request.form['station_name']
        station_id = request.form['station_id']
        staff_name = request.form['staff_name']
        contact_no = request.form['contact_no']
        station_location = request.form['station_location']
        username = request.form['username']
        password = request.form['password']
        verify_password = request.form['verify_password']

        # Check if station_id already exists in the database
        existing_station = users_collection.find_one({'station_id': station_id})
        if existing_station:
            flash('Station ID already exists. Please use a different Station ID.', 'danger')
            return redirect(url_for('register'))

        # Check if username already exists in the database
        existing_user = users_collection.find_one({'username': username})
        if existing_user:
            flash('Username already taken. Please choose a different username.', 'danger')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != verify_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        if password == verify_password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            user_data = {
                'user': session['username'],
                'sub_district_name': sub_district_name,
                'registrant_name': registrant_name,
                'station_name': station_name,
                'station_id': station_id,
                'staff_name': staff_name,
                'contact_no': contact_no,
                'station_location': station_location,
                'username': username,
                'password': hashed_password
            }

            users_collection.insert_one(user_data)
            flash('Registration successful!', 'success')
            return redirect(url_for('register'))
        else:
            flash('Passwords do not match', 'danger')

    return render_template('adminRegister.html')



@app.route('/manage_user')
def manage_user():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    # Query all users' data from the database
    users_data = list(users_collection.find())

    return render_template('adminManageUser.html', users_data=users_data)




@app.route('/edit/<user_id>', methods=['GET', 'POST'])
def edit(user_id):
    user = users_collection.find_one({'_id': ObjectId(user_id)})
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('manage_user'))

    if request.method == 'POST':
        sub_district_name = request.form['sub_district_name']
        registrant_name = request.form['registrant_name']
        station_name = request.form['station_name']
        station_id = request.form['station_id']
        staff_name = request.form['staff_name']
        contact_no = request.form['contact_no']
        station_location = request.form['station_location']
        username = request.form['username']
        password = request.form['password']
        verify_password = request.form['verify_password']

        # Validation: Check if all required fields are provided
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('edit.html', user=user)

        # Validation: Check if the username meets the minimum length requirement
        if len(username) < 8:
            flash('Username must be at least 8 characters long', 'danger')
            return render_template('edit.html', user=user)

        # Validation: Check if the password meets the minimum length requirement
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
            return render_template('edit.html', user=user)

        # Validation: Ensure the station_id is unique (excluding the current user's station_id)
        existing_station = users_collection.find_one({'station_id': station_id, '_id': {'$ne': ObjectId(user_id)}})
        if existing_station:
            flash('Station ID already exists. Please use a different Station ID.', 'danger')
            return render_template('edit.html', user=user)

        # Validation: Ensure the username is unique (excluding the current user's username)
        existing_user = users_collection.find_one({'username': username, '_id': {'$ne': ObjectId(user_id)}})
        if existing_user:
            flash('Username already taken. Please choose a different username.', 'danger')
            return render_template('edit.html', user=user)

        # Validation: Check if the passwords match
        if password != verify_password:
            flash("Passwords do not match", 'danger')
            return render_template('edit.html', user=user)

        # Hash the password if it is provided and valid
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Update the user details in the database
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {
                "$set": {
                    'sub_district_name': sub_district_name,
                    'registrant_name': registrant_name,
                    'station_name': station_name,
                    'station_id': station_id,
                    'staff_name': staff_name,
                    'contact_no': contact_no,
                    'station_location': station_location,
                    'username': username,
                    'password': hashed_password
                }
            }
        )
        flash("User edited successfully", 'success')
        return redirect(url_for('manage_user'))

    # GET request: Render the form with the current user details
    return render_template('edit.html', user=user)





















# User Routes
@app.route('/home')
def home():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/warehousetable')
def warehousetable():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('warehousetable.html')

@app.route('/adddetails', methods=['GET', 'POST'])

@app.route('/adddetails', methods=['GET', 'POST'])
def add_details():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        fir_number = request.form['fir_number']
        inspector = request.form['inspector']
        crime_date = request.form['crime_date']
        item_seized = request.form['item_seized']
        crime_place = request.form['crime_place']
        item_condition = request.form['item_condition']
        witness = request.form['witness']
        storage_location = request.form['storage_location']
        ipc_section = request.form['ipc_section']
        number_plate = request.form.get('number_plate', '')

        # Generate a Unique ID
        unique_id = str(uuid.uuid4())

        # Prepare data to encode in the QR code
        qr_data = f"""
        FIR Number: {fir_number}
        Inspector: {inspector}
        Crime Date: {crime_date}
        Item Seized: {item_seized}
        Crime Place: {crime_place}
        Item Condition: {item_condition}
        Witness: {witness}
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
        img_str = base64.b64encode(buffered.getvalue()).decode()

        # Save evidence data along with unique ID and QR code image (base64 encoded)
        evidence_data = {
            'username': session['username'],
            'fir_number': fir_number,
            'inspector': inspector,
            'crime_date': crime_date,
            'item_seized': item_seized,
            'crime_place': crime_place,
            'item_condition': item_condition,
            'witness': witness,
            'storage_location': storage_location,
            'ipc_section': ipc_section,
            'number_plate': number_plate,
            'unique_id': unique_id,
            'qr_code': img_str  # Storing the QR code image as base64
        }

        evidence_collection.insert_one(evidence_data)
        flash('Evidence details added successfully!', 'success')

        # Render the template and pass the QR code image and unique ID to be displayed
        return render_template('adddetails.html', qr_code=img_str, unique_id=unique_id)

    return render_template('adddetails.html')

@app.route('/viewdetails')
def view_details():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    evidence_details = evidence_collection.find({'username': session['username']})
    return render_template('viewdetails.html', evidence_details=evidence_details)

# Check-in and Check-out Routes
@app.route('/checkin')
def checkin():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    checkin_details = checkin_collection.find({'username': session['username']})
    return render_template('CheckIn.html', checkin_details=checkin_details)

@app.route('/checkout')
def checkout():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    checkout_details = checkout_collection.find({'username': session['username']})
    return render_template('CheckOut.html', checkout_details=checkout_details)




# Storage Checker Routes
@app.route('/storagechecker')
def storage_checker():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('storageChecker.html')

@app.route('/setstoragechecker')
def set_storage_checker():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    user = checkout_collection.find({'username': session['username']})
    return render_template('setStorageChecker.html', user=user)















# Global Search
@app.route('/globalsearch', methods=['GET', 'POST'])
def global_search():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        search_query = request.form.get('search')
        query = {
            "$or": [
                {"number_plate": {"$regex": search_query, "$options": "i"}},
                {"item_seized": {"$regex": search_query, "$options": "i"}},
                {"crime_date": {"$regex": search_query, "$options": "i"}},
                {"storage_location": {"$regex": search_query, "$options": "i"}}
            ]
        }
        results = evidence_collection.find(query)
        return render_template('GlobalSearch.html', result=results)
    
    return render_template('GlobalSearch.html')

@app.route('/readDetails/<evidence_id>')
def read_details1(evidence_id):
    # Find the evidence by its ID
    if 'username' not in session:
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
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('CourtHelper.html')

@app.route('/checkin_court', methods=['GET', 'POST'])
def checkin_court():
    if 'username' not in session:
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
            'username': session['username'],
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

    return render_template('Check_In_from_Court.html')

@app.route('/checkout_court', methods=['GET', 'POST'])
def checkout_court():
    if 'username' not in session:
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
            'username': session['username'],
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

    return render_template('Check_out_from_Court.html')





















# FSL Table Routes
@app.route('/fsltable')
def fsl_helper():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('FslHelper.html')

@app.route('/checkout_fsl', methods=['GET', 'POST'])
def checkout_fsl():
    if 'username' not in session:
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
            'username': session['username'],
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
        return redirect(url_for('checkout_fsl'))

    return render_template('Check_out_from_FSL.html')


@app.route('/searchinfsl', methods=['POST'])
def searchinfsl():
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
    
    return render_template('Check_In_from_FSL.html', evidence=evidence)

@app.route('/searchoutfsl', methods=['POST'])
def searchoutfsl():
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
    
    return render_template('Check_In_from_Court.html', evidence=evidence)





@app.route('/checkin_fsl', methods=['GET', 'POST'])
def checkin_fsl():
    if 'username' not in session:
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
            'username': session['username'],
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
        return redirect(url_for('checkin_fsl'))

    return render_template('Check_In_from_FSL.html')

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
