# 🏪 Smart Udhaar — Full Setup Instructions

## 📁 Project Structure
```
smart-udhaar/
├── backend/
│   ├── main.py           ← FastAPI backend (all routes)
│   └── requirements.txt  ← Python dependencies
└── frontend/
    └── index.html        ← Complete UI (single file, no build needed)
```

---

## ⚙️ BACKEND SETUP (Python + FastAPI)

### Step 1 — Install Python
Make sure Python 3.10+ is installed:
```bash
python --version
```
Download from https://python.org if not installed.

---

### Step 2 — Create & activate virtual environment
```bash
# Create project folder
mkdir smart-udhaar && cd smart-udhaar
mkdir backend frontend

# Create virtual environment
python -m venv venv

# Activate it
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate
```

---

### Step 3 — Install dependencies
Paste `main.py` and `requirements.txt` into the `backend/` folder, then:
```bash
cd backend
pip install -r requirements.txt
```

---

### Step 4 — Run the backend
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Application startup complete.
```

A file called `udhaar.db` (SQLite database) will be created automatically in the `backend/` folder.

---

### Step 5 — Test the API
Open your browser and go to:
```
http://localhost:8000/docs
```
This opens the **Swagger UI** — you can test all API endpoints here.

---

## 🌐 FRONTEND SETUP (Pure HTML — No build needed!)

### Step 1 — Save the file
Paste `index.html` into your `frontend/` folder.

### Step 2 — Configure the API URL
Open `index.html` and find this line near the top of the `<script>` section:
```javascript
const API = "http://localhost:8000";
```
This points to your local backend. Change it when you deploy.

### Step 3 — Open in browser
Just double-click `index.html` or open it in Chrome/Firefox.

> ⚠️ **CORS Note:** The backend is already configured to allow all origins (`*`). If you get a CORS error, make sure your backend is running.

---

## 🗄️ DATABASE

### Using SQLite (default — for development)
No setup needed. The file `udhaar.db` is created automatically.

### Switch to PostgreSQL (for production)
1. Install PostgreSQL and create a database:
```sql
CREATE DATABASE udhaar_db;
CREATE USER udhaar_user WITH PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE udhaar_db TO udhaar_user;
```

2. Set the environment variable before running:
```bash
# Mac/Linux
export DATABASE_URL="postgresql://udhaar_user:yourpassword@localhost/udhaar_db"

# Windows
set DATABASE_URL=postgresql://udhaar_user:yourpassword@localhost/udhaar_db
```

3. Install psycopg2:
```bash
pip install psycopg2-binary
```

---

## 🔐 SECURITY CONFIGURATION

Before going live, change the secret key:
```bash
export SECRET_KEY="your-super-secret-random-string-here"
```

Or create a `.env` file:
```
SECRET_KEY=your-super-secret-random-string-here
DATABASE_URL=sqlite:///./udhaar.db
```

Then install `python-dotenv` and add to `main.py`:
```python
from dotenv import load_dotenv
load_dotenv()
```

---

## 🚀 DEPLOYMENT

### Backend → Render (Free tier)

1. Push your `backend/` folder to GitHub
2. Go to https://render.com → New → Web Service
3. Connect your GitHub repo
4. Set these:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add Environment Variables:
   - `SECRET_KEY` → your secret
   - `DATABASE_URL` → your PostgreSQL URL (Render provides free PostgreSQL)
6. Deploy!

### Frontend → Netlify (Free)

1. Go to https://netlify.com → Drop your `frontend/` folder
2. It deploys instantly
3. Update `const API = "https://your-render-app.onrender.com"` in `index.html`

### Frontend → Vercel (Free)

```bash
npm i -g vercel
cd frontend
vercel
```

---

## 📡 ALL API ENDPOINTS

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Login, get JWT token |
| GET  | `/auth/me` | Get current user info |
| GET  | `/dashboard` | Full dashboard data |
| GET  | `/customers` | List all customers with balances |
| POST | `/customers` | Add new customer |
| GET  | `/customers/{id}` | Customer detail + full ledger |
| POST | `/transactions` | Add credit or payment |
| GET  | `/products` | List all products with stock status |
| POST | `/products` | Add new product |
| PATCH | `/products/{id}/restock` | Add stock to product |
| GET  | `/sales` | List all sales |
| POST | `/sales` | Record a sale (auto-deducts stock, auto-creates udhaar for credit) |
| GET  | `/reminders` | Customers with overdue balances |

---

## 🛡️ KEY BUSINESS LOGIC (Built-in)

| Rule | Where |
|------|-------|
| Payment cannot exceed balance | `/transactions` endpoint |
| Sale blocked if stock < quantity | `/sales` endpoint |
| Credit sale auto-creates udhaar | `/sales` endpoint |
| Low stock alert (quantity ≤ threshold) | `/products` + `/dashboard` |
| Overdue = balance > 0 AND last credit > 10 days | `/reminders` + `/dashboard` |
| JWT token expires after 7 days | Auth system |

---

## ⚡ QUICK TEST FLOW

1. Run backend: `uvicorn main:app --reload`
2. Open `index.html` in browser
3. Click **Register** → create account
4. Go to **Customers** → Add customer "Ravi"
5. Click Ravi's card → Open Khata
6. Click **Add Udhaar** → ₹500
7. Go to **Inventory** → Add "Sugar 1kg" at ₹45, qty 20
8. Go to **Sales** → Record credit sale of Sugar to Ravi
9. Go to **Reminders** → See Ravi's balance
10. Go to **Dashboard** → See all stats + chart

---

## 🔥 RESUME LINE

> "Built a full-stack inventory and credit management system for small kirana businesses using Python (FastAPI) and vanilla HTML/CSS/JS, featuring JWT authentication, real-time stock tracking, customer credit ledger with overpayment prevention, automated payment reminders, and a Chart.js sales dashboard."

---

## 💡 NEXT LEVEL FEATURES TO ADD

- **WhatsApp reminders** → Twilio API or Meta WhatsApp Cloud API
- **Export to PDF/Excel** → ReportLab (Python) or jsPDF (frontend)
- **Multi-shop (SaaS)** → Already supported! Each user_id is isolated
- **SMS OTP login** → Replace password with OTP via Fast2SMS
- **Barcode scanning** → Use `html5-qrcode` library in frontend
