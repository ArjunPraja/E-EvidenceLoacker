# from tkinter import *
# from tkinter import messagebox
# from PIL import Image, ImageTk
# import sqlite3


# class malkhana:

# #-----------------------------------L-O-G-I-N----------------------------------------------------------------------------

#     def __init__(self) -> None:
#         # Function to check login credentials
#         def check_credentials():
#             username = userE.get()
#             password = passw.get()

#             # Connect to the SQLite database (create it if it doesn't exist)
#             conn = sqlite3.connect("log.db")
#             cursor = conn.cursor()

#             # Check if the username and password match a record in the database
#             cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
#             user = cursor.fetchone()

#             conn.close()

#             if user:
#                 messagebox.showinfo("Login Successful", "Welcome, " + username + "!")
#                 root.destroy()
#                 self.home()
#             else:
#                 messagebox.showerror("Login Failed", "Invalid username or password")


#         root = Tk()
#         root.title("LogInPage")

#         # Open the original image using PIL
#         original_image = Image.open("/Users/vaibhavamrit/FINAL YEAR PROJECT/GUI/login.jpg")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # User name Label and Entry

#         userE = Entry(root, width=15, font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         userE.place(x=670, y=257)

#         # Password Label and Entry

#         passw = Entry(root, width=15, font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         passw.place(x=670, y=350)
#         passw.config(show='*')  # Show asterisks for password characters

#         # Login Button
#         def login():
#             # Define the login functionality here
#             check_credentials()

#         loginButton = Button(root, width=15, text="Login", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=login, relief="flat")
#         loginButton.place(x=595, y=435)


#         # Create a database table for user credentials (if it doesn't exist)
#         conn = sqlite3.connect("log.db")
#         cursor = conn.cursor()
#         cursor.execute('''
#             CREATE TABLE IF NOT EXISTS users (
#                 id INTEGER PRIMARY KEY,
#                 username TEXT,
#                 password TEXT
#             )
#         ''')
#         conn.close()


#         root.mainloop()


# #----------------------------------H-O-M-E-----------------------------------------------------------------------------


#     def home(self):
        
#         root = Tk()
#         root.title("Home Page")

#         # Open the original image using PIL
#         original_image = Image.open("Home.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         #Malkhana Table

#         def mclicked():
#             root.destroy()
#             self.malkhana_table()

#         m = Button(root, width=15, text="Malkhana Table", font=('Open Sans', 18, 'bold'), bg='#CFCDCD', fg='black', command=mclicked, relief="flat")
#         m.place(x=100, y=30)

#         # FSL Table

#         def fclicked():
#             self.fsl_data()

#         fsl = Button(root, width=15, text="Checkout from fsl Table", font=('Open Sans', 18, 'bold'), bg='#CFCDCD', fg='black', command=fclicked, relief="flat")
#         fsl.place(x=400, y=30)

#         # Logs Table

#         def cclicked():
#             self.court_data()

#         court = Button(root, width=17, text="Checkout from Court Table", font=('Open Sans', 18, 'bold'), bg='#CFCDCD', fg='black', command=cclicked, relief="flat")
#         court.place(x=700, y=30)

#         #Logout Buttobn

#         def logoutclicked():
#             messagebox.showinfo("Logout Successful", "Looged Out Successfully")
#             root.destroy()
#             self.__init__()

#         lout = Button(root, width=15, text="Logout", font=('Open Sans', 18, 'bold'), bg='#CFCDCD', fg='black', command=logoutclicked, relief="flat")
#         lout.place(x=400, y=606)

#         root.mainloop()


# #-------------------------------F-S-L-D-A-T-A--------------------------------------------------------------------------------


#     def fsl_data(self):
#         root = Tk()
#         root.title("Check Out from FSL")


#         conn = sqlite3.connect("checkout_fsl_database.db")
#         cursor = conn.cursor()
#         cursor.execute("PRAGMA table_info(checkout)")
#         columns = [column[1] for column in cursor.fetchall()]  # Get the column names
#         cursor.execute("SELECT * FROM checkout")
#         data = cursor.fetchall()
#         conn.close()

#         for i, column_name in enumerate(columns):
#             label = Label(root, text=column_name, font=('Open Sans', 12, 'bold'))
#             label.grid(row=2, column=i, padx=5, pady=5)

#         for i, record in enumerate(data):
#             for j, value in enumerate(record):
#                 label = Label(root, text=str(value), font=('Open Sans', 12))
#                 label.grid(row=i + 3, column=j, padx=5, pady=5)

#         root.mainloop()

    
# #--------------------------------C-O-U-R-T-D-A-T-A-------------------------------------------------------------------------------


#     def court_data(self):
#         root = Tk()
#         root.title("Check Out from Court")


#         conn = sqlite3.connect("checkout_court_database.db")
#         cursor = conn.cursor()
#         cursor.execute("PRAGMA table_info(checkout)")
#         columns = [column[1] for column in cursor.fetchall()]  # Get the column names
#         cursor.execute("SELECT * FROM checkout")
#         data = cursor.fetchall()
#         conn.close()

#         for i, column_name in enumerate(columns):
#             label = Label(root, text=column_name, font=('Open Sans', 12, 'bold'))
#             label.grid(row=2, column=i, padx=5, pady=5)

#         for i, record in enumerate(data):
#             for j, value in enumerate(record):
#                 label = Label(root, text=str(value), font=('Open Sans', 12))
#                 label.grid(row=i + 3, column=j, padx=5, pady=5)



#         # Create a section for displaying data from the "checkout_fsl_database.db" database
#         Label(root, text="Court Database", font=('Open Sans', 15, 'bold')).grid(row=1, column=1)


#         root.mainloop()


# #------------------------------M-A-L-K-H-A-N-A---T-A-B-L-E---------------------------------------------------------------------------------


#     def malkhana_table(self):
#         root = Tk()
#         root.title("Malkhana Table")

#         # Open the original image using PIL
#         original_image = Image.open("Malkhana Table.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # ADD

#         def addclicked():
#             root.destroy()
#             self.malkhana_add()

#         add = Button(root, width=15, text="ADD", font=('Open Sans', 18, 'bold'), bg='#FFFFFF', fg='black', command=addclicked, relief="flat")
#         add.place(x=102, y=200)

#         # Check in items

#         def ciclicked():
#             root.destroy()
#             self.check_in()

#         checkin = Button(root, width=15, text="Checkin", font=('Open Sans', 18, 'bold'), bg='#FFFFFF', fg='black', command=ciclicked, relief="flat")
#         checkin.place(x=102, y=420)

#         # View items

#         def show_data_gui():
            
#             conn = sqlite3.connect("malkhana.db")
#             cursor = conn.cursor()

#             # Execute an SQL query to retrieve data from the database
#             cursor.execute("SELECT * FROM users")
#             data = cursor.fetchall()

#             cursor.execute("PRAGMA table_info(users)")
#             column_names = [row[1] for row in cursor.fetchall()]

#             conn.close()

#             data_window = Toplevel(root)  # Create a new window
#             data_window.title("Data from Database")

#             # Create labels for column names
#             for col, name in enumerate(column_names):
#                 label = Label(data_window, text=name, font=('Open Sans', 12, 'bold'))
#                 label.grid(row=0, column=col)

#             # Display the data with column names
#             for row_idx, record in enumerate(data):
#                 for col_idx, value in enumerate(record):
#                     label = Label(data_window, text=value, font=('Open Sans', 12))
#                     label.grid(row=row_idx + 1, column=col_idx)

#             data_window.mainloop()


#         view = Button(root, width=15, text="View Items", font=('Open Sans', 18, 'bold'), bg='#FFFFFF', fg='black', command=show_data_gui, relief="flat")
#         view.place(x=712, y=200)

#         # Check out item

#         def coclicked():
#             root.destroy()
#             self.check_out()

#         checkout = Button(root, width=15, text="Check Out", font=('Open Sans', 18, 'bold'), bg='#FFFFFF', fg='black', command=coclicked, relief="flat")
#         checkout.place(x=712, y=420)

#         # Back Button
#         def back():
#             root.destroy()
#             self.home()

#         backButton = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backButton.place(x=113, y=607)


#         # Logout Button
#         def logout():
#             messagebox.showinfo("Logout Successful", "Logged out Successfully")
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=607)

#         root.mainloop()


# #-------------------------------M-A-L-K-H-A-N-A---A-D-D--------------------------------------------------------------------------------


#     def malkhana_add(self):
#         root = Tk()
#         root.title("Malkhan ADD")

#         def create_database_table():
#             conn = sqlite3.connect("malkhana.db")
#             cursor = conn.cursor()
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS users (
#                     id INTEGER PRIMARY KEY,
#                     barcode TEXT,
#                     fir_number TEXT,
#                     inspector TEXT,
#                     crime_date TEXT,
#                     item_seized TEXT,
#                     crime_place TEXT,
#                     item_condition TEXT,
#                     witness TEXT,
#                     location TEXT,
#                     ipc_section TEXT
#                 )
#             ''')
#             conn.commit()
#             conn.close()

#         def add_data():
#             create_database_table()  # Ensure the table exists

#             # Retrieve data from Tkinter Entry widgets
#             barcode = barcode_entry.get()
#             fir_number = fir_number_entry.get()
#             inspector = inspector_entry.get()
#             crime_date = crime_date_entry.get()
#             item_seized = item_seized_entry.get()
#             crime_place = crime_place_entry.get()
#             item_condition = item_condition_entry.get()
#             witness = witness_entry.get()
#             location = location_entry.get()
#             ipc_section = ipc_section_entry.get()

#             if not all([barcode, fir_number, inspector, crime_date, item_seized, crime_place, item_condition, witness, location, ipc_section]):
#                 messagebox.showerror("Error", "Please fill in all fields.")

#             else:

#                 conn = sqlite3.connect("malkhana.db")
#                 cursor = conn.cursor()

#                 # Execute an SQL INSERT query to add data to the database
#                 cursor.execute('''
#                     INSERT INTO users (barcode, fir_number, inspector, crime_date, item_seized, crime_place, item_condition, witness, location, ipc_section)
#                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
#                 ''', (barcode, fir_number, inspector, crime_date, item_seized, crime_place, item_condition, witness, location, ipc_section))

#                 conn.commit()
#                 conn.close()

#                 # Display a success message
#                 messagebox.showinfo("Success", "Data added to the database")
#                 root.destroy()
#                 self.malkhana_table()



#         # Open the original image using PIL
#         original_image = Image.open("Malkhana ADD.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # Barcode Entry

#         barcode_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         barcode_entry.place(x=210, y=122)

#         # Inspector Entry

#         inspector_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         inspector_entry.place(x=210, y=200)

#         # Item Seized Entry

#         item_seized_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         item_seized_entry.place(x=210, y=278)

#         # Item Condition Entry

#         item_condition_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         item_condition_entry.place(x=210, y=355)

#         # Storage Location Entry

#         location_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         location_entry.place(x=210, y=434)



#         # FIR Number Entry

#         fir_number_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         fir_number_entry.place(x=781, y=122)

#         # Crime Date Entry

#         crime_date_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         crime_date_entry.place(x=781, y=200)

#         # Crime Place Entry

#         crime_place_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         crime_place_entry.place(x=781, y=278)

#         #  Witness Entry

#         witness_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         witness_entry.place(x=781, y=355)

#         # IPC Section Entry

#         ipc_section_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         ipc_section_entry.place(x=781, y=434)


#         # ADD Button

#         addb = Button(root, width=15, text="ADD", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=add_data, relief="flat")
#         addb.place(x=400, y=525)


#         # Back Button
#         def back():
#             root.destroy()
#             self.malkhana_table()

#         backb = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backb.place(x=113, y=595)


#         # Logout Button
#         def logout():
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=595)

#         root.mainloop()


# #-----------------------------------C-H-E-C-K---O-U-T----------------------------------------------------------------------------


#     def check_out(self):

#         root = Tk()
#         root.title("Check Out")

#         # Open the original image using PIL
#         original_image = Image.open("/Users/vaibhavamrit/FINAL YEAR PROJECT/GUI/Check Out.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # Check Out from FSL
#         def checkoutfsl():
#             root.destroy()
#             self.checkoutfsl()


#         checkoutf = Button(root, width=15, text="Check out From FSL", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=checkoutfsl, relief="flat")
#         checkoutf.place(x=113, y=307)

#         # Check out from Court
#         def checkoutcourt():
#             root.destroy()
#             self.checkoutcourt()

#         checkoutf = Button(root, width=15, text="Check out From Court", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=checkoutcourt, relief="flat")
#         checkoutf.place(x=645, y=307)


#         # Back Button
#         def back():
#             root.destroy()
#             self.malkhana_table()

#         backButton = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backButton.place(x=113, y=607)


#         # Logout Button
#         def logout():
#             messagebox.showinfo("Logout Successful", "Logged out Successfully")
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=607)

#         root.mainloop()


# #--------------------C-H-E-C-K---O-U-T---F-S-L-------------------------------------------------------------------------------------------

#     def checkoutfsl(self):
#         def create_database():
#             # Connect to the SQLite database (or create it if it doesn't exist)
#             conn = sqlite3.connect("checkout_fsl_database.db")
#             cursor = conn.cursor()

#             # Create a table to store the checkout data
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS checkout (
#                     barcode TEXT,
#                     fir_number TEXT,
#                     item TEXT,
#                     collected TEXT,
#                     check_out_date TEXT,
#                     check_out_time TEXT,
#                     order_number TEXT
#                 )
#             ''')

#             # Commit the changes and close the database connection
#             conn.commit()
#             conn.close()

#         def save_to_database():
#             # Retrieve data from the Tkinter Entry fields
#             barcode = barcode_entry.get()
#             fir_number = fir_number_entry.get()
#             item = item_entry.get()
#             collected = collected_entry.get()
#             check_out_date = check_out_date_entry.get()
#             check_out_time = check_out_time_entry.get()
#             order_number = order_number_entry.get()

#             # Check if any of the fields are empty
#             if not all([barcode, fir_number, item, collected, check_out_date, check_out_time, order_number]):
#                 messagebox.showerror("Error", "Please fill in all fields.")
#             else:
#                 # Connect to the database
#                 conn = sqlite3.connect("checkout_fsl_database.db")
#                 cursor = conn.cursor()

#                 # Insert data into the "checkout" table
#                 cursor.execute('''
#                     INSERT INTO checkout (barcode, fir_number, item, collected, check_out_date, check_out_time, order_number)
#                     VALUES (?, ?, ?, ?, ?, ?, ?)
#                 ''', (barcode, fir_number, item, collected, check_out_date, check_out_time, order_number))

#                 # Commit changes and close the database connection
#                 conn.commit()
#                 conn.close()

#                 # Display a success message
#                 messagebox.showinfo("Success", "Data added to the database")


#         root = Tk()
#         root.title("Check Out from FSL")

#         # Open the original image using PIL
#         original_image = Image.open("/Users/vaibhavamrit/FINAL YEAR PROJECT/GUI/Check Out from fsl.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # Barcode Entry

#         barcode_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         barcode_entry.place(x=210, y=122)

#         # FIR Number Entry

#         fir_number_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         fir_number_entry.place(x=781, y=122)

#         # Item Seized Entry

#         item_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         item_entry.place(x=210, y=270)

#         # Collected Entry

#         collected_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         collected_entry.place(x=781, y=270)

#         # Check Out date Entry

#         check_out_date_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_date_entry.place(x=210, y=395)

#         # Check Out time Entry

#         check_out_time_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_time_entry.place(x=781, y=395)

#         # Order Number Entry
#         order_number_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         order_number_entry.place(x=210, y=483)

#         # Save Button
#         save_button = Button(root, text="Save to Database", font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', command=save_to_database, relief="flat")
#         save_button.place(x=450, y=545)

#         # Create the database if it doesn't exist
#         create_database()


#         # Back Button
#         def back():
#             root.destroy()
#             self.check_out()

#         backb = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backb.place(x=113, y=595)


#         # Logout Button
#         def logout():
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=595)

#         root.mainloop()


# #---------------C-H-E-C-K---O-U-T---C-O-U-R-T------------------------------------------------------------------------------------------------

#     def checkoutcourt(self):
#         def create_database():
#             # Connect to the SQLite database (or create it if it doesn't exist)
#             conn = sqlite3.connect("checkout_court_database.db")
#             cursor = conn.cursor()

#             # Create a table to store the checkout data
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS checkout (
#                     barcode TEXT,
#                     fir_number TEXT,
#                     item TEXT,
#                     collected TEXT,
#                     check_out_date TEXT,
#                     check_out_time TEXT,
#                     order_number TEXT
#                 )
#             ''')

#             # Commit the changes and close the database connection
#             conn.commit()
#             conn.close()

#         def save_to_database():
#             # Retrieve data from the Tkinter Entry fields
#             barcode = barcode_entry.get()
#             fir_number = fir_number_entry.get()
#             item = item_entry.get()
#             collected = collected_entry.get()
#             check_out_date = check_out_date_entry.get()
#             check_out_time = check_out_time_entry.get()
            

#             # Check if any of the fields are empty
#             if not all([barcode, fir_number, item, collected, check_out_date, check_out_time]):
#                 messagebox.showerror("Error", "Please fill in all fields.")
#             else:
#                 # Connect to the database
#                 conn = sqlite3.connect("checkout_court_database.db")
#                 cursor = conn.cursor()

#                 # Insert data into the "checkout" table
#                 cursor.execute('''
#                 INSERT INTO checkout (barcode, fir_number, item, collected, check_out_date, check_out_time)
#                 VALUES (?, ?, ?, ?, ?, ?)
#                 ''', (barcode, fir_number, item, collected, check_out_date, check_out_time))


#                 # Commit changes and close the database connection
#                 conn.commit()
#                 conn.close()

#                 # Display a success message
#                 messagebox.showinfo("Success", "Data added to the database")
#                 root.destroy()
#                 self.check_out()


#         root = Tk()
#         root.title("Check Out from Court")

#         # Open the original image using PIL
#         original_image = Image.open("/Users/vaibhavamrit/FINAL YEAR PROJECT/GUI/Check Out from court.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # Barcode Entry

#         barcode_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         barcode_entry.place(x=210, y=122)

#         # FIR Number Entry

#         fir_number_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         fir_number_entry.place(x=781, y=122)

#         # Item Seized Entry

#         item_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         item_entry.place(x=210, y=270)

#         # Collected Entry

#         collected_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         collected_entry.place(x=781, y=270)

#         # Check Out date Entry

#         check_out_date_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_date_entry.place(x=210, y=395)

#         # Check Out time Entry

#         check_out_time_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_time_entry.place(x=781, y=395)

#         # Save Button
#         save_button = Button(root, text="Save to Database", font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', command=save_to_database, relief="flat")
#         save_button.place(x=450, y=545)

#         # Create the database if it doesn't exist
#         create_database()


#         # Back Button
#         def back():
#             root.destroy()
#             self.check_out()

#         backb = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backb.place(x=113, y=595)


#         # Logout Button
#         def logout():
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=595)

#         root.mainloop()

# #-----------------------------------C-H-E-C-K---I-N-----------------------------------------------------------------------------


#     def check_in(self):

#         root = Tk()
#         root.title("Check In")

#         # Open the original image using PIL
#         original_image = Image.open("/Users/vaibhavamrit/FINAL YEAR PROJECT/GUI try/Check In.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # Check In from FSL
#         def checkinfsl():
#             root.destroy()
#             self.check_in_fsl()


#         checkinf = Button(root, width=15, text="Check In From FSL", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=checkinfsl, relief="flat")
#         checkinf.place(x=113, y=307)

#         # Check in from Court
#         def checkincourt():
#             root.destroy()
#             self.check_in_court()

#         checkinc = Button(root, width=15, text="Check In From Court", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=checkincourt, relief="flat")
#         checkinc.place(x=645, y=307)


#         # Back Button
#         def back():
#             root.destroy()
#             self.malkhana_table()

#         backButton = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backButton.place(x=113, y=607)


#         # Logout Button
#         def logout():
#             messagebox.showinfo("Logout Successful", "Logged out Successfully")
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=607)

#         root.mainloop()

# #--------------------C-H-E-C-K---I-N---C-O-U-R-T-------------------------------------------------------------------------------------------

#     def check_in_court(self):
#         def create_database():
#             # Connect to the SQLite database (or create it if it doesn't exist)
#             conn = sqlite3.connect("checkin_court_database.db")
#             cursor = conn.cursor()

#             # Create a table to store the checkout data
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS checkout (
#                     barcode TEXT,
#                     order_details TEXT,
#                     item TEXT,
#                     collected TEXT,
#                     check_in_date TEXT,
#                     check_in_time TEXT,
#                     order_number TEXT
#                 )
#             ''')

#             # Commit the changes and close the database connection
#             conn.commit()
#             conn.close()

#         def save_to_database():
#             # Retrieve data from the Tkinter Entry fields
#             barcode = barcode_entry.get()
#             order_details = order_details_entry.get()
#             item = item_entry.get()
#             collected = collected_entry.get()
#             check_out_date = check_out_date_entry.get()
#             check_out_time = check_out_time_entry.get()
#             order_number = order_number_entry.get()

#             # Check if any of the fields are empty
#             if not all([barcode, order_details, item, collected, check_out_date, check_out_time, order_number]):
#                 messagebox.showerror("Error", "Please fill in all fields.")
#             else:
#                 # Connect to the database
#                 conn = sqlite3.connect("checkin_court_database.db")
#                 cursor = conn.cursor()

#                 # Insert data into the "checkout" table
#                 cursor.execute('''
#                     INSERT INTO checkout (barcode, order_details, item, collected, check_in_date, check_in_time, order_number)
#                     VALUES (?, ?, ?, ?, ?, ?, ?)
#                 ''', (barcode, order_details, item, collected, check_out_date, check_out_time, order_number))

#                 # Commit changes and close the database connection
#                 conn.commit()
#                 conn.close()

#                 # Display a success message
#                 messagebox.showinfo("Success", "Checked In Successfully")


#         root = Tk()
#         root.title("Check In from Court")

#         # Open the original image using PIL
#         original_image = Image.open("/Users/vaibhavamrit/FINAL YEAR PROJECT/GUI try/Check In from court.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # Barcode Entry

#         barcode_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         barcode_entry.place(x=210, y=122)

#         # Order details

#         order_details_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         order_details_entry.place(x=781, y=122)

#         # Item Seized Entry

#         item_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         item_entry.place(x=210, y=270)

#         # Collected Entry

#         collected_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         collected_entry.place(x=781, y=270)

#         # Check Out date Entry

#         check_out_date_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_date_entry.place(x=210, y=395)

#         # Check Out time Entry

#         check_out_time_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_time_entry.place(x=781, y=395)

#         # Order Number Entry
#         order_number_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         order_number_entry.place(x=210, y=483)

#         # Save Button
#         save_button = Button(root, text="Save to Database", font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', command=save_to_database, relief="flat")
#         save_button.place(x=450, y=545)

#         # Create the database if it doesn't exist
#         create_database()


#         # Back Button
#         def back():
#             root.destroy()
#             self.check_in()

#         backb = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backb.place(x=113, y=595)


#         # Logout Button
#         def logout():
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=595)

#         root.mainloop()


# #--------------------C-H-E-C-K---I-N---F-S-L-------------------------------------------------------------------------------------------

#     def check_in_fsl(self):
#         def create_database():
#             # Connect to the SQLite database (or create it if it doesn't exist)
#             conn = sqlite3.connect("checkin_fsl_database.db")
#             cursor = conn.cursor()

#             # Create a table to store the checkout data
#             cursor.execute('''
#                 CREATE TABLE IF NOT EXISTS checkout (
#                     barcode TEXT,
#                     eaximer_report TEXT,
#                     item TEXT,
#                     collected TEXT,
#                     check_in_date TEXT,
#                     check_in_time TEXT,
#                     order_number TEXT
#                 )
#             ''')

#             # Commit the changes and close the database connection
#             conn.commit()
#             conn.close()

#         def save_to_database():
#             # Retrieve data from the Tkinter Entry fields
#             barcode = barcode_entry.get()
#             examiner_report = examiner_report_entry.get()
#             item = item_entry.get()
#             collected = collected_entry.get()
#             check_out_date = check_out_date_entry.get()
#             check_out_time = check_out_time_entry.get()
#             order_number = order_number_entry.get()

#             # Check if any of the fields are empty
#             if not all([barcode, examiner_report, item, collected, check_out_date, check_out_time, order_number]):
#                 messagebox.showerror("Error", "Please fill in all fields.")
#             else:
#                 # Connect to the database
#                 conn = sqlite3.connect("checkin_fsl_database.db")
#                 cursor = conn.cursor()

#                 # Insert data into the "checkout" table
#                 cursor.execute('''
#                     INSERT INTO checkout (barcode, examiner_report, item, collected, check_in_date, check_in_time, order_number)
#                     VALUES (?, ?, ?, ?, ?, ?, ?)
#                 ''', (barcode, examiner_report, item, collected, check_out_date, check_out_time, order_number))

#                 # Commit changes and close the database connection
#                 conn.commit()
#                 conn.close()

#                 # Display a success message
#                 messagebox.showinfo("Success", "Checked In Successfully")
#                 root.destroy()
#                 self.check_in()


#         root = Tk()
#         root.title("Check In from Fsl")

#         # Open the original image using PIL
#         original_image = Image.open("/Users/vaibhavamrit/FINAL YEAR PROJECT/GUI try/Check in from fsl.png")

#         # Resize the image to your desired dimensions
#         new_width = 1000
#         new_height = 650
#         resized_image = original_image.resize((new_width, new_height))

#         # Create an ImageTk.PhotoImage object from the resized image
#         resized_photo = ImageTk.PhotoImage(resized_image)

#         bg_label = Label(root, image=resized_photo)
#         bg_label.grid(row=0, column=0)

#         root.geometry(f"{new_width}x{new_height}")

#         # Barcode Entry

#         barcode_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         barcode_entry.place(x=210, y=122)

#         # Examiner Report

#         examiner_report_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         examiner_report_entry.place(x=781, y=122)

#         # Item Seized Entry

#         item_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         item_entry.place(x=210, y=270)

#         # Collected Entry

#         collected_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         collected_entry.place(x=781, y=270)

#         # Check Out date Entry

#         check_out_date_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_date_entry.place(x=210, y=395)

#         # Check Out time Entry

#         check_out_time_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         check_out_time_entry.place(x=781, y=395)

#         # Order Number Entry
#         order_number_entry = Entry(root, width=15, font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', relief="flat")
#         order_number_entry.place(x=210, y=483)

#         # Save Button
#         save_button = Button(root, text="Save to Database", font=('Open Sans', 15, 'bold'), bg='#EEEDED', fg='black', command=save_to_database, relief="flat")
#         save_button.place(x=450, y=545)

#         # Create the database if it doesn't exist
#         create_database()


#         # Back Button
#         def back():
#             root.destroy()
#             self.check_in()

#         backb = Button(root, width=15, text="Back", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=back, relief="flat")
#         backb.place(x=113, y=595)


#         # Logout Button
#         def logout():
#             root.destroy()
#             self.__init__()

#         logoutButton = Button(root, width=15, text="Logout", font=('Open Sans', 20, 'bold'), bg='#EEEDED', fg='black', command=logout, relief="flat")
#         logoutButton.place(x=645, y=595)

#         root.mainloop()


# mlk = malkhana()