from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymongo
import bcrypt
import os
from bson import ObjectId
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
        
        if password == verify_password:
            
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
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
            return redirect(url_for('manage_user'))
        else:
            return "Passwords do not match!"
    
    user = users_collection.find_one({'_id': ObjectId(user_id)})
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
            'number_plate': number_plate
        }

        evidence_collection.insert_one(evidence_data)
        flash('Evidence details added successfully!', 'success')
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

# Global Search Routes
@app.route('/globalsearch')
def global_search():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('GlobalSearch.html')

@app.route('/readdetails')
def read_details():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('GlobalReadDetails.html')

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
