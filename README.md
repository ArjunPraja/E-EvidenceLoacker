# E-Evidence Locker

**E-Evidence Locker** is a web-based application built to manage the *Malkhana* (evidence room) in police stations. The system enables efficient tracking and management of evidence during its lifecycle, from check-in to forensic analysis, court proceedings, and final disposal. It provides a comprehensive solution for ensuring transparency, accountability, and ease of access to evidence records.

## Features

- **Warehouse Module**: 
  - Add, view, check-in, and check-out evidence.
  - Keep track of evidence status during its storage in the warehouse.
  
- **Forensic Laboratory Module**: 
  - Manage data transactions related to evidence sent to forensic labs.
  
- **Court Module**: 
  - Track evidence transactions during court proceedings.

- **Global Search**: 
  - Allows police officers to search and view evidence records from any location. 
  - Supports case-based searches, enabling officers to access case-related evidence quickly.

- **User Authentication**: 
  - Only authenticated users with valid police email IDs can log in.
  - Ensures that only authorized personnel can view and manage evidence records.

## Modules Overview

1. **Warehouse Module**: 
   - Enables police officers to add evidence details, view evidence, check-in new evidence, and check-out evidence for further use or investigation.
  
2. **Forensic Laboratory Module**: 
   - Allows police officers to log and track the movement of evidence to and from forensic labs.

3. **Court Module**: 
   - Provides a view and tracking of evidence that is used or needed for court proceedings, ensuring its proper handling and usage during trials.

4. **Global Search for Investigation**: 
   - A powerful search function that lets officers search for evidence based on various parameters, enabling them to find the information they need for ongoing investigations.

## Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Database**: MongoDB
- **Authentication**: Email-based login system restricted to police email IDs.

## Installation

To run this project locally, follow these steps:

1. **Clone the repository**:

   ```bash
   git clone https://github.com/ArjunPraja/E-EvidenceLoacker.git
   ```

2. **Navigate to the project directory**:

   ```bash
   cd E-EvidenceLoacker
   ```

3. **Install the required dependencies**:

   ```bash
   pip install -r Package Name
   ```

4. **Set up MongoDB**:

   - Ensure MongoDB is installed and running on your machine.
   - Modify the connection string in the application to point to your MongoDB instance.

5. **Run the application**:

   ```bash
   flask run
   ```

6. **Access the application**:

   Open your browser and go to `http://localhost:5000`.

## Usage

1. **Login**: Use a valid police email ID to log in to the system.
2. **Add Evidence**: Enter the necessary details in the warehouse module to add new evidence.
3. **Search Evidence**: Use the global search functionality to search for evidence based on case number, type, or other parameters.
4. **Track Transactions**: Track evidence movement between the warehouse, forensic labs, and courts.
5. **Check-In/Check-Out Evidence**: Use the warehouse module to check in or check out evidence for further use.

## Contributions

Contributions to improve the project are welcome! Please fork the repository, make your changes, and submit a pull request.


## Contact

For any inquiries or suggestions, feel free to contact:
**Arjun Vishnubhai Prajapati**  
Email: [prajapatiarjun2801@example.com](mailto:prajapatiarjun2801@example.com)  
GitHub: [ArjunPraja](https://github.com/ArjunPraja)


