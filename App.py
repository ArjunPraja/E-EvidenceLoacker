from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymongo
import bcrypt
import os

# Create a Flask application
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'Prajapati Arjun')  # Secret key for session management

# Database Connection
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client['E_Evidence_Locker']
users_collection = db['users']
evidence_collection = db['evidence']  # Collection to store evidence data
admins_collection = db['admins']  # Store Admins Data
global_search_collection = db['globalsearch']
Ceckin = db['Checkin']
Checkout = db['Checkout']

# Authentication Part
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





 
@app.route('/admin')
def admin():
    if 'username' not in session or session.get('role')!='admin':
        flash('Access Denied','danger')
        return redirect(url_for(login))
    return render_template('admin.html')



@app.route('/register')
def register():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_submit():
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
                'user':session[username],
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
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match', 'danger')

    return render_template('register.html')

# Home
@app.route('/home')
def home():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('home.html')

# Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))






# Warehouse Table
@app.route('/warehousetable')
def warehousetable():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('warehousetable.html')



# Add Evidence Details
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
            'number_plate':number_plate

        }

        evidence_collection.insert_one(evidence_data)
        flash('Evidence details added successfully!', 'success')
    return render_template('adddetails.html')

# View Evidence Details
@app.route('/viewdetails')
def view_details():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    evidence_details = evidence_collection.find({'username':session['username']})  # Fetch all evidence details
    return render_template('viewdetails.html', evidence_details=evidence_details)

# Check-in and Check-out for Warehouse Table
@app.route('/checkin')
def checkin():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    # Fetch check-in details for the logged-in user
    checkin_details = Ceckin.find({'username': session['username']})
    return render_template('CheckIn.html', checkin_details=checkin_details)

@app.route('/checkout')
def checkout():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    # Fetch check-out details for the logged-in user
    checkout_details = Checkout.find({'username': session['username']})
    return render_template('CheckOut.html', checkout_details=checkout_details)









# Storage Checker
@app.route('/storagechecker')
def storage_checker():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('storageChecker.html' )


@app.route('/setstoragechecker')
def set_storage_checker():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    

    user = Checkout.find({'username': session['username']})
    return render_template('setStorageChecker.html',user=user)
    










# Global Search
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










# Court Table
@app.route('/courttable')
def court_helper():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('CourtHelper.html')

@app.route('/checkin_court', methods=['GET','POST'])
def checkin_court():
    if request.method == 'POST':
        
        barcode_number = request.form['barcode_number']
        fir_number = request.form['fir_number']
        item_name = request.form['item_name']
        collected_by = request.form['collected_by']
        checkin_date = request.form['checkin_date']
        checkin_time = request.form['checkin_time']
        remarks=request.form['remarks']
         
        
        checkin_data = {
            'username': session['username'],
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkin_date': checkin_date,
            'checkin_time': checkin_time,
            'remarks':remarks,
            
        }
        
        Ceckin.insert_one(checkin_data)   
        
         
        flash('Checked in successfully!', 'success')
        return redirect(url_for('checkin_court'))

    return render_template('Check_In_from_Court.html')

@app.route('/checkout_court', methods=['GET','POST'])
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
        remarks=request.form['remarks']
        
        checkout_data = {
            'username': session['username'],
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkout_date': checkout_date,
            'checkout_time': checkout_time,
            'remarks':remarks
        }
        
        Checkout.insert_one(checkout_data)  # Insert data into Checkout collection in MongoDB
        
        flash('Checked out successfully!', 'success')
        return redirect(url_for('checkout_court'))

    return render_template('Check_out_from_Court.html')

































# FSL Table
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
        remarks=request.form['remarks']
        
        checkout_data = {
            'username': session['username'],
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkout_date': checkout_date,
            'checkout_time': checkout_time,
            
        }
        
        Checkout.insert_one(checkout_data)  # Insert data into Checkout collection in MongoDB
        
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
        remarks=request.form['remarks']
         
        
        checkin_data = {
            'username': session['username'],
            'barcode_number': barcode_number,
            'fir_number': fir_number,
            'item_name': item_name,
            'collected_by': collected_by,
            'checkin_date': checkin_date,
            'checkin_time': checkin_time,
            'remarks':remarks,
             
            
        }
        
        Ceckin.insert_one(checkin_data)  # Insert data into Checkin collection in MongoDB
        
        flash('Checked in successfully!', 'success')
        return redirect(url_for('checkin_fsl'))
    
    return render_template('Check_In_from_FSL.html')








# Under Construction
@app.route('/underconstruction')
def under_construction():
    if 'username' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))
    return render_template('underConstruction.html')

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
