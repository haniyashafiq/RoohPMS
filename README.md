# Rooh Rehab - Patient Management System

A comprehensive Flask-based Patient Management System for rehabilitation centers with features for patient records, user management, session notes, medical records, and canteen management.

## Features

- **User Management** - Role-based access control (Admin, Doctor, Psychologist, Canteen)
- **Patient Management** - Complete patient profiles with admission details
- **Medical Records** - Track medical observations and treatments
- **Session Notes** - Document therapy and counseling sessions
- **Canteen Management** - Track patient expenses and monthly allowances
- **Data Export** - Export patient data to Excel
- **Dashboard Metrics** - Real-time statistics and insights

## Technology Stack

- **Backend**: Flask (Python)
- **Database**: MongoDB Atlas
- **Frontend**: HTML, Tailwind CSS, JavaScript
- **Deployment**: Vercel-ready

## Local Setup

### Prerequisites

- Python 3.8 or higher
- MongoDB Atlas account (free tier available)
- Git

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd RoohPMS
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

1. Copy `.env.example` to `.env`:

   ```bash
   # Windows
   copy .env.example .env

   # macOS/Linux
   cp .env.example .env
   ```

2. Edit `.env` file with your configuration:

   ```env
   # MongoDB Configuration
   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/RoohRehab?appName=Cluster0

   # Flask Configuration
   SECRET_KEY=your_secret_key_here_change_in_production

   # Default Admin Configuration
   DEFAULT_ADMIN_USERNAME=ImranSaab
   DEFAULT_ADMIN_PASSWORD=password123
   DEFAULT_ADMIN_NAME=Imran Khan
   ```

### Step 5: Set Up MongoDB Atlas

1. **Create MongoDB Atlas Account**:
   - Go to [https://www.mongodb.com/cloud/atlas](https://www.mongodb.com/cloud/atlas)
   - Sign up for a free account

2. **Create a Cluster**:
   - Click "Build a Database"
   - Choose the FREE tier (M0)
   - Select a cloud provider and region

3. **Create Database User**:
   - Go to "Database Access"
   - Add a new database user with username and password
   - Grant "Read and write to any database" permission

4. **Configure Network Access**:
   - Go to "Network Access"
   - Add IP Address: `0.0.0.0/0` (allow from anywhere) for development
   - For production, restrict to specific IPs

5. **Get Connection String**:
   - Go to "Database" → Click "Connect"
   - Choose "Connect your application"
   - Copy the connection string
   - Replace `<password>` with your database user password
   - Add your database name (e.g., `RoohRehab`) between `.net/` and `?`

   Example:

   ```
   mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/RoohRehab?appName=Cluster0
   ```

6. **Update `.env` file** with your MongoDB URI

### Step 6: Seed the Database (Optional)

Populate the database with sample data for testing:

```bash
python seed_database.py
```

This creates:

- 4 users (Admin, Doctor, Psychologist, Canteen Staff)
- 5 sample patients
- 7 patient records (medical records and session notes)
- 44 canteen sales transactions

### Step 7: Run the Application

```bash
python app.py
```

The application will be available at: **http://localhost:5000**

### Step 8: Login

Use one of these default credentials:

| Role          | Username      | Password    |
| ------------- | ------------- | ----------- |
| Admin         | ImranSaab     | password123 |
| Doctor        | dr_ahmed      | doctor123   |
| Psychologist  | psych_sara    | psych123    |
| Canteen Staff | canteen_staff | canteen123  |

**⚠️ Important**: Change these passwords after first login!

## Vercel Deployment

### Step 1: Prepare for Deployment

1. Ensure `vercel.json` is configured correctly
2. Ensure `.env` is in `.gitignore` (already configured)

### Step 2: Deploy to Vercel

1. **Install Vercel CLI** (optional):

   ```bash
   npm install -g vercel
   ```

2. **Deploy via Vercel Dashboard**:
   - Go to [https://vercel.com](https://vercel.com)
   - Import your Git repository
   - Configure project settings

3. **Set Environment Variables**:
   - Go to Project Settings → Environment Variables
   - Add the following variables:
     - `MONGO_URI` - Your MongoDB Atlas connection string
     - `SECRET_KEY` - A secure random string for session management
     - `DEFAULT_ADMIN_USERNAME` - Admin username
     - `DEFAULT_ADMIN_PASSWORD` - Admin password (change after deployment)
     - `DEFAULT_ADMIN_NAME` - Admin display name

4. **Deploy**:
   - Click "Deploy"
   - Vercel will automatically build and deploy your application

### Step 3: Seed Production Database

After deployment, run the seed script against your production database:

```bash
# Update .env with production MONGO_URI
python seed_database.py
```

## Project Structure

```
RoohPMS/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── seed_database.py        # Database seeding script
├── check_database.py       # Database verification script
├── vercel.json            # Vercel configuration
├── .env                   # Environment variables (not in git)
├── .env.example           # Environment variables template
├── .gitignore             # Git ignore rules
├── static/                # Static files (CSS, JS, images)
├── templates/             # HTML templates
│   └── index.html        # Main application UI
└── README.md             # This file
```

## API Endpoints

### Authentication

- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/session` - Check session status

### Users (Admin only)

- `GET /api/users` - Get all users
- `POST /api/users` - Create new user
- `DELETE /api/users/<id>` - Delete user
- `POST /api/users/change_password` - Change password

### Patients

- `GET /api/patients` - Get all patients
- `POST /api/patients` - Add new patient
- `PUT /api/patients/<id>` - Update patient
- `DELETE /api/patients/<id>` - Delete patient (Admin only)

### Patient Records

- `POST /api/patients/<id>/session_note` - Add session note
- `POST /api/patients/<id>/medical_record` - Add medical record
- `GET /api/patients/<id>/records` - Get all records for patient

### Canteen (Admin/Canteen only)

- `POST /api/canteen/sales` - Record canteen sale
- `GET /api/canteen/sales/breakdown` - Get monthly breakdown

### Dashboard

- `GET /api/dashboard/metrics` - Get dashboard statistics

### Export

- `POST /api/export` - Export patient data to Excel

## User Roles and Permissions

| Feature            | Admin | Doctor | Psychologist | Canteen |
| ------------------ | ----- | ------ | ------------ | ------- |
| Dashboard          | ✓     | ✓      | ✓            | ✗       |
| View Patients      | ✓     | ✓      | ✓            | ✗       |
| Add/Edit Patients  | ✓     | ✓      | ✗            | ✗       |
| Delete Patients    | ✓     | ✗      | ✗            | ✗       |
| Medical Records    | ✓     | ✓      | ✗            | ✗       |
| Session Notes      | ✓     | ✗      | ✓            | ✗       |
| User Management    | ✓     | ✗      | ✗            | ✗       |
| Canteen Management | ✓     | ✗      | ✗            | ✓       |
| Data Export        | ✓     | ✗      | ✗            | ✗       |

## Troubleshooting

### Database Connection Issues

**Problem**: "Database connection failed or not initialized"

**Solutions**:

1. Verify `MONGO_URI` in `.env` file
2. Check MongoDB Atlas network access settings
3. Ensure database user has correct permissions
4. Verify database name in connection string

### Empty Tables After Login

**Problem**: User management or canteen tables are empty

**Solutions**:

1. Clear browser cache and cookies
2. Try in incognito/private window
3. Check browser console for 403 errors
4. Verify you're logged in with correct role
5. Run `python check_database.py` to verify data exists

### Session/Authentication Issues

**Problem**: Getting logged out frequently

**Solutions**:

1. Ensure `SECRET_KEY` is set in `.env`
2. Don't use the same `SECRET_KEY` in multiple environments
3. Check that cookies are enabled in browser

### Deployment Issues

**Problem**: App crashes on Vercel

**Solutions**:

1. Check Vercel logs for errors
2. Verify all environment variables are set
3. Ensure MongoDB Atlas allows connections from `0.0.0.0/0`
4. Check that `vercel.json` is correctly configured

## Database Schema

### Users Collection

```javascript
{
  _id: ObjectId,
  username: String,
  password: String (hashed),
  role: String, // 'Admin', 'Doctor', 'Psychologist', 'Canteen'
  name: String,
  created_at: Date
}
```

### Patients Collection

```javascript
{
  _id: ObjectId,
  name: String,
  fatherName: String,
  admissionDate: String,
  idNo: String,
  age: String,
  cnic: String,
  contactNo: String,
  address: String,
  complaint: String,
  guardianName: String,
  relation: String,
  drugProblem: String,
  maritalStatus: String,
  prevAdmissions: String,
  monthlyFee: String,
  monthlyAllowance: String,
  created_at: Date,
  notes: Array
}
```

### Patient Records Collection

```javascript
{
  _id: ObjectId,
  patient_id: ObjectId,
  text: String,
  type: String, // 'session_note' or 'medical_record'
  date: Date,
  recorded_by: String
}
```

### Canteen Sales Collection

```javascript
{
  _id: ObjectId,
  patient_id: ObjectId,
  item: String,
  amount: Number,
  date: Date,
  recorded_by: String
}
```

## Security Considerations

1. **Change Default Passwords**: Always change default admin password after first login
2. **Secret Key**: Use a strong, random SECRET_KEY in production
3. **Environment Variables**: Never commit `.env` file to version control
4. **MongoDB Access**: Restrict IP addresses in production
5. **HTTPS**: Always use HTTPS in production (Vercel provides this automatically)
6. **Password Hashing**: All passwords are hashed using Werkzeug security

## Backup and Maintenance

### Database Backup

Use MongoDB Atlas built-in backup features:

1. Go to your cluster in Atlas
2. Navigate to "Backup" tab
3. Enable cloud backups (available in paid tiers)

Or use `mongodump`:

```bash
mongodump --uri="your_connection_string"
```

### Restore Database

```bash
mongorestore --uri="your_connection_string" dump/
```

## Support

For issues or questions:

1. Check the Troubleshooting section
2. Review MongoDB Atlas documentation
3. Check Flask documentation: [https://flask.palletsprojects.com](https://flask.palletsprojects.com)

## License

[Add your license information here]

## Contributing

[Add contribution guidelines if applicable]
