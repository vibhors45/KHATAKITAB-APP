from fastapi.responses import FileResponse
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, Float, Enum, Date, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base
from pydantic import BaseModel
from typing import Optional
from datetime import date, datetime, timedelta
import hashlib, hmac, json, base64, os, enum, threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

# ─── APP ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="HisabKitab API", version="3.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ══════════════════════════════════════════════════════════════════════════════
# 📧 EMAIL CONFIG
# ──────────────────────────────────────────────────────────────────────────────
# STEP 1: Create a Gmail account e.g.  hisabkitab.app@gmail.com
# STEP 2: Gmail → Settings → Security → 2-Step Verification → App Passwords
#         Generate App Password for "Mail" → paste the 16-char code below
# STEP 3: Replace the two values below (or set as environment variables)
# ══════════════════════════════════════════════════════════════════════════════
GMAIL_USER     = "khatakitabapp@gmail.com"   # ← replace
GMAIL_APP_PASS = "niks hmjr qitl cxug"   # ← replace
GMAIL_NAME     = "KhataKitab"

# ─── DATABASE ─────────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./udhaar.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ─── JWT ──────────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "hisabkitab-super-secret-2025")
security   = HTTPBearer()

def make_token(payload: dict) -> str:
    header    = base64.urlsafe_b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip("=")
    body      = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig_input = f"{header}.{body}".encode()
    sig       = hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).hexdigest()
    return f"{header}.{body}.{sig}"

def verify_token(token: str) -> dict:
    try:
        header, body, sig = token.split(".")
        sig_input = f"{header}.{body}".encode()
        expected  = hmac.new(SECRET_KEY.encode(), sig_input, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("Bad signature")
        padding = 4 - len(body) % 4
        data = json.loads(base64.urlsafe_b64decode(body + "=" * padding))
        if data.get("exp", 0) < datetime.utcnow().timestamp():
            raise ValueError("Token expired")
        return data
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    return verify_token(creds.credentials)

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

# ─── MODELS ───────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id        = Column(Integer, primary_key=True, index=True)
    name      = Column(String, nullable=False)
    email     = Column(String, unique=True, index=True, nullable=False)
    password  = Column(String, nullable=False)
    shop_name = Column(String, default="My Dukaan")
    phone     = Column(String, default="")

class Customer(Base):
    __tablename__ = "customers"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False)
    name         = Column(String, nullable=False)
    phone        = Column(String, nullable=False)
    address      = Column(String, default="")
    email        = Column(String, default="")        # ✅ customer email for receipts
    created_at   = Column(Date, default=date.today)
    transactions = relationship("Transaction", back_populates="customer")

class TransactionType(str, enum.Enum):
    credit  = "credit"
    payment = "payment"

class Transaction(Base):
    __tablename__ = "transactions"
    id          = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount      = Column(Float, nullable=False)
    type        = Column(Enum(TransactionType), nullable=False)
    note        = Column(String, default="")
    date        = Column(Date, default=date.today)
    customer    = relationship("Customer", back_populates="transactions")

class Product(Base):
    __tablename__ = "products"
    id        = Column(Integer, primary_key=True, index=True)
    user_id   = Column(Integer, ForeignKey("users.id"), nullable=False)
    name      = Column(String, nullable=False)
    price     = Column(Float, nullable=False)
    quantity  = Column(Integer, nullable=False, default=0)
    unit      = Column(String, default="kg")
    threshold = Column(Integer, default=5)

class SaleType(str, enum.Enum):
    cash   = "cash"
    credit = "credit"

class Sale(Base):
    __tablename__ = "sales"
    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_id  = Column(Integer, ForeignKey("products.id"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    quantity    = Column(Integer, nullable=False)
    amount      = Column(Float, nullable=False)
    type        = Column(Enum(SaleType), nullable=False)
    date        = Column(Date, default=date.today)

# Create all tables
Base.metadata.create_all(bind=engine)

# ── Auto-add new columns to existing databases (safe upgrade) ─────────────────
def _add_col(table, col, col_type="VARCHAR DEFAULT ''"):
    try:
        import sqlalchemy
        with engine.connect() as conn:
            conn.execute(sqlalchemy.text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}"))
            conn.commit()
    except Exception:
        pass  # column already exists

_add_col("users",     "phone")
_add_col("customers", "email")

# ══════════════════════════════════════════════════════════════════════════════
# 📧 EMAIL HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _send_email(to: str, subject: str, html: str, pdf_bytes: bytes = None, pdf_name: str = None):
    """Fire-and-forget email in a background thread."""
    def _worker():
        try:
            msg = MIMEMultipart("mixed")
            msg["Subject"] = subject
            msg["From"]    = f"{GMAIL_NAME} <{GMAIL_USER}>"
            msg["To"]      = to
            msg.attach(MIMEText(html, "html", "utf-8"))

            if pdf_bytes and pdf_name:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(pdf_bytes)
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f'attachment; filename="{pdf_name}"')
                msg.attach(part)

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
                s.login(GMAIL_USER, GMAIL_APP_PASS)
                s.sendmail(GMAIL_USER, to, msg.as_string())
            print(f"✅ Email sent → {to}")
        except Exception as e:
            print(f"❌ Email failed → {to}: {e}")

    threading.Thread(target=_worker, daemon=True).start()


def _email_welcome(name: str, shop: str, to: str):
    html = f"""
    <div style="font-family:'Segoe UI',sans-serif;max-width:540px;margin:auto;background:#0d0f14;
                color:#eceef5;border-radius:16px;overflow:hidden;border:1px solid #252835">
      <div style="background:linear-gradient(135deg,#6366f1,#7c3aed);padding:36px;text-align:center">
        <h1 style="margin:0;font-size:28px;letter-spacing:-1px">📒 HisabKitab</h1>
        <p style="margin:8px 0 0;opacity:.8;font-size:14px">Smart Dukaan Management</p>
      </div>
      <div style="padding:32px">
        <h2 style="color:#6366f1;margin-top:0">Namaste {name} ji! 🙏</h2>
        <p style="line-height:1.7">Aapka <strong>{shop}</strong> ab HisabKitab par registered hai.<br>
        Ab aap apni dukaan ka poora hisaab digitally manage kar sakte ho!</p>
        <div style="background:#13161e;border-radius:10px;padding:18px;margin:20px 0">
          <p style="margin:0 0 10px;font-weight:600">🚀 Aap kar sakte ho:</p>
          <p style="margin:4px 0;color:#9ca3af">📒 Customer ka udhaar track</p>
          <p style="margin:4px 0;color:#9ca3af">📦 Inventory management</p>
          <p style="margin:4px 0;color:#9ca3af">📊 Sales analytics & charts</p>
          <p style="margin:4px 0;color:#9ca3af">🤖 AI Dukaan Assistant</p>
          <p style="margin:4px 0;color:#9ca3af">💬 WhatsApp payment reminders</p>
          <p style="margin:4px 0;color:#9ca3af">📧 Email bill receipts</p>
        </div>
        <p style="color:#6b7280;font-size:13px">Registration time: {datetime.now().strftime('%d %b %Y, %I:%M %p')}</p>
      </div>
      <div style="padding:16px 32px;background:#13161e;border-top:1px solid #252835;
                  text-align:center;color:#6b7280;font-size:12px">
        HisabKitab — Aapki dukaan ka digital hisaab · Do not reply to this email
      </div>
    </div>"""
    _send_email(to, f"🎉 HisabKitab par Welcome, {name} ji!", html)


def _email_password_reset(name: str, to: str):
    html = f"""
    <div style="font-family:'Segoe UI',sans-serif;max-width:540px;margin:auto;background:#0d0f14;
                color:#eceef5;border-radius:16px;overflow:hidden;border:1px solid #252835">
      <div style="background:linear-gradient(135deg,#6366f1,#7c3aed);padding:36px;text-align:center">
        <h1 style="margin:0;font-size:28px">🔐 HisabKitab</h1>
      </div>
      <div style="padding:32px">
        <h2 style="margin-top:0">Password Reset Ho Gaya ✅</h2>
        <p>Namaste <strong>{name}</strong> ji,</p>
        <p style="line-height:1.7">Aapka HisabKitab account ka password successfully reset ho gaya hai.</p>
        <div style="background:#ef444420;border:1px solid #ef444440;border-radius:10px;padding:16px;margin:20px 0">
          <p style="margin:0;color:#ef4444;font-weight:600">⚠️ Agar aapne yeh nahi kiya?</p>
          <p style="margin:6px 0 0;color:#9ca3af;font-size:14px">Turant apna password dobara change karein aur support se contact karein.</p>
        </div>
        <p style="color:#6b7280;font-size:13px">Reset time: {datetime.now().strftime('%d %b %Y, %I:%M %p')}</p>
      </div>
      <div style="padding:16px 32px;background:#13161e;border-top:1px solid #252835;
                  text-align:center;color:#6b7280;font-size:12px">
        HisabKitab — Do not reply to this email
      </div>
    </div>"""
    _send_email(to, "HisabKitab — Password Reset Confirmation 🔐", html)


def _email_receipt(shop: str, owner: str, cust_name: str, cust_email: str,
                   txns: list, balance: float, pdf_bytes: bytes = None):
    rows_html = "".join([
        f"""<tr>
          <td style="padding:10px 12px;border-bottom:1px solid #252835">{t['date']}</td>
          <td style="padding:10px 12px;border-bottom:1px solid #252835">
            <span style="background:{'rgba(251,146,60,.15)' if t['type']=='credit' else 'rgba(34,197,94,.15)'};
                         color:{'#fb923c' if t['type']=='credit' else '#22c55e'};
                         border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700">
              {t['type'].upper()}
            </span>
          </td>
          <td style="padding:10px 12px;border-bottom:1px solid #252835;font-weight:700">₹{t['amount']:,.0f}</td>
          <td style="padding:10px 12px;border-bottom:1px solid #252835;color:#9ca3af">{t.get('note','—')}</td>
        </tr>"""
        for t in txns
    ])
    bal_color  = "#ef4444" if balance > 0 else "#22c55e"
    bal_label  = "💰 Baaki Balance" if balance > 0 else "✅ Balance Clear"
    bal_msg    = "<p style='color:#ef4444'>Kripya jald settle karein. Dhanyavaad! 🙏</p>" if balance > 0 \
                 else "<p style='color:#22c55e'>Shukriya! Aapka khata bilkul clear hai. 🎉</p>"

    html = f"""
    <div style="font-family:'Segoe UI',sans-serif;max-width:620px;margin:auto;background:#0d0f14;
                color:#eceef5;border-radius:16px;overflow:hidden;border:1px solid #252835">
      <div style="background:linear-gradient(135deg,#6366f1,#7c3aed);padding:32px;text-align:center">
        <h1 style="margin:0;font-size:24px">📒 {shop}</h1>
        <p style="margin:6px 0 0;opacity:.85;font-size:13px">Khata Bill Receipt</p>
      </div>
      <div style="padding:28px">
        <p>Namaste <strong>{cust_name}</strong> ji 🙏</p>
        <p style="color:#9ca3af;font-size:14px">Neeche aapka <strong style="color:#eceef5">{shop}</strong> ka complete khata statement hai:</p>
        <table style="width:100%;border-collapse:collapse;background:#13161e;border-radius:10px;
                      overflow:hidden;margin:16px 0;font-size:14px">
          <thead>
            <tr style="background:#191c26">
              <th style="padding:12px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase">Date</th>
              <th style="padding:12px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase">Type</th>
              <th style="padding:12px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase">Amount</th>
              <th style="padding:12px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase">Note</th>
            </tr>
          </thead>
          <tbody>{rows_html}</tbody>
        </table>
        <div style="background:#13161e;border:2px solid {bal_color};border-radius:10px;
                    padding:16px 20px;display:flex;justify-content:space-between;align-items:center;
                    margin-bottom:16px">
          <span style="font-weight:600;font-size:15px">{bal_label}</span>
          <span style="font-size:26px;font-weight:800;color:{bal_color}">₹{abs(balance):,.0f}</span>
        </div>
        {bal_msg}
        <p style="color:#6b7280;font-size:13px;margin-top:20px">
          Koi sawaal? <strong>{owner}</strong> se contact karein.
          {"<br>📎 PDF receipt is attached with this email." if pdf_bytes else ""}
        </p>
      </div>
      <div style="padding:16px 28px;background:#13161e;border-top:1px solid #252835;
                  text-align:center;color:#6b7280;font-size:12px">
        Sent via HisabKitab · {date.today().strftime('%d %b %Y')} · Do not reply
      </div>
    </div>"""

    pdf_name = f"Khata_{cust_name.replace(' ','_')}_{date.today()}.pdf" if pdf_bytes else None
    _send_email(cust_email, f"{shop} — Aapka Khata Statement 📒", html, pdf_bytes, pdf_name)


# ─── DATE HELPER ──────────────────────────────────────────────────────────────
def parse_date(raw: Optional[str]) -> date:
    if not raw or not raw.strip():
        return date.today()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw.strip(), fmt).date()
        except ValueError:
            continue
    return date.today()


# ─── SCHEMAS ──────────────────────────────────────────────────────────────────
class RegisterIn(BaseModel):
    name: str
    email: str
    password: str
    shop_name: str = "My Dukaan"
    phone: str = ""

class LoginIn(BaseModel):
    email: str
    password: str

class ForgotPasswordIn(BaseModel):
    email: str

class ResetPasswordIn(BaseModel):
    email: str
    new_password: str

class CustomerIn(BaseModel):
    name: str
    phone: str
    address: str = ""
    email: str = ""          # ✅ customer email for receipts

class TransactionIn(BaseModel):
    customer_id: int
    amount: float
    type: TransactionType
    note: str = ""
    date: Optional[str] = None

class ProductIn(BaseModel):
    name: str
    price: float
    quantity: int
    unit: str = "kg"
    threshold: int = 5

class RestockIn(BaseModel):
    quantity: int

class SaleIn(BaseModel):
    product_id: int
    quantity: int
    type: SaleType
    customer_id: Optional[int] = None
    date: Optional[str] = None

class SendReceiptIn(BaseModel):
    customer_id: int
    pdf_base64: Optional[str] = None   # base64-encoded PDF from frontend


# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/auth/register", tags=["Auth"])
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(name=data.name, email=data.email,
                password=hash_password(data.password),
                shop_name=data.shop_name, phone=data.phone)
    db.add(user); db.commit(); db.refresh(user)
    # ✅ Send welcome email
    _email_welcome(data.name, data.shop_name, data.email)
    return {"message": "Registered successfully", "user_id": user.id}


@app.post("/auth/login", tags=["Auth"])
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email    == data.email,
        User.password == hash_password(data.password)
    ).first()
    if not user:
        raise HTTPException(401, "Invalid email or password")
    exp   = (datetime.utcnow() + timedelta(days=7)).timestamp()
    token = make_token({"sub": user.id, "email": user.email, "exp": exp})
    return {
        "token": token,
        "user": {"id": user.id, "name": user.name,
                 "shop_name": user.shop_name, "phone": user.phone or ""}
    }


@app.get("/auth/me", tags=["Auth"])
def me(current=Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current["sub"]).first()
    return {"id": user.id, "name": user.name, "email": user.email,
            "shop_name": user.shop_name, "phone": user.phone or ""}


@app.post("/auth/forgot-password", tags=["Auth"])
def forgot_password(data: ForgotPasswordIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        return {"exists": False}
    return {"exists": True, "name": user.name}


@app.post("/auth/reset-password", tags=["Auth"])
def reset_password(data: ResetPasswordIn, db: Session = Depends(get_db)):
    if len(data.new_password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(404, "No account found with this email")
    user.password = hash_password(data.new_password)
    db.commit()
    # ✅ Send reset confirmation email
    _email_password_reset(user.name, user.email)
    return {"message": "Password reset successfully"}


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOMER ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/customers", tags=["Customers"])
def list_customers(current=Depends(get_current_user), db: Session = Depends(get_db)):
    customers = db.query(Customer).filter(Customer.user_id == current["sub"]).all()
    result = []
    for c in customers:
        txns    = db.query(Transaction).filter(Transaction.customer_id == c.id).all()
        balance = sum(t.amount if t.type == "credit" else -t.amount for t in txns)
        result.append({
            "id": c.id, "name": c.name, "phone": c.phone,
            "address": c.address, "email": c.email or "",
            "created_at": str(c.created_at), "balance": round(balance, 2)
        })
    return result


@app.post("/customers", tags=["Customers"])
def add_customer(data: CustomerIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    c = Customer(user_id=current["sub"], name=data.name, phone=data.phone,
                 address=data.address, email=data.email)
    db.add(c); db.commit(); db.refresh(c)
    return {"id": c.id, "name": c.name, "phone": c.phone,
            "address": c.address, "email": c.email, "balance": 0}


@app.get("/customers/{cid}", tags=["Customers"])
def get_customer(cid: int, current=Depends(get_current_user), db: Session = Depends(get_db)):
    c = db.query(Customer).filter(Customer.id == cid, Customer.user_id == current["sub"]).first()
    if not c:
        raise HTTPException(404, "Customer not found")
    txns    = db.query(Transaction).filter(Transaction.customer_id == cid).order_by(Transaction.date).all()
    balance = 0; ledger = []
    for t in txns:
        balance += t.amount if t.type == "credit" else -t.amount
        ledger.append({"id": t.id, "amount": t.amount, "type": t.type,
                       "note": t.note, "date": str(t.date),
                       "running_balance": round(balance, 2)})
    return {"id": c.id, "name": c.name, "phone": c.phone,
            "address": c.address, "email": c.email or "",
            "balance": round(balance, 2), "transactions": ledger}


# ✅ NEW: Send bill receipt to customer via email (+ optional PDF attachment)
@app.post("/customers/{cid}/send-receipt", tags=["Customers"])
def send_receipt(cid: int, data: SendReceiptIn,
                 current=Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current["sub"]).first()
    c    = db.query(Customer).filter(Customer.id == cid, Customer.user_id == current["sub"]).first()
    if not c:
        raise HTTPException(404, "Customer not found")
    if not c.email:
        raise HTTPException(400, "Is customer ka email nahi hai. Pehle customer ka email add karein.")

    txns    = db.query(Transaction).filter(Transaction.customer_id == cid).order_by(Transaction.date).all()
    balance = sum(t.amount if t.type == "credit" else -t.amount for t in txns)
    txn_list = [{"date": str(t.date), "type": t.type,
                 "amount": t.amount, "note": t.note} for t in txns]

    pdf_bytes = None
    if data.pdf_base64:
        try:
            pdf_bytes = base64.b64decode(data.pdf_base64)
        except Exception:
            pass

    _email_receipt(user.shop_name, user.name, c.name, c.email,
                   txn_list, round(balance, 2), pdf_bytes)
    return {"message": f"✅ Receipt {c.name} ko email kar diya! ({c.email})"}


# ══════════════════════════════════════════════════════════════════════════════
# TRANSACTION ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/transactions", tags=["Udhaar"])
def add_transaction(data: TransactionIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    c = db.query(Customer).filter(
        Customer.id == data.customer_id, Customer.user_id == current["sub"]
    ).first()
    if not c:
        raise HTTPException(404, "Customer not found")

    if data.type == "payment":
        txns    = db.query(Transaction).filter(Transaction.customer_id == data.customer_id).all()
        balance = sum(t.amount if t.type == "credit" else -t.amount for t in txns)
        if data.amount > balance:
            raise HTTPException(400, f"Payment ₹{data.amount} exceeds balance ₹{round(balance,2)}")

    t = Transaction(user_id=current["sub"], customer_id=data.customer_id,
                    amount=data.amount, type=data.type,
                    note=data.note, date=parse_date(data.date))
    db.add(t); db.commit(); db.refresh(t)
    return {"id": t.id, "amount": t.amount, "type": t.type,
            "note": t.note, "date": str(t.date)}


# ══════════════════════════════════════════════════════════════════════════════
# INVENTORY ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/products", tags=["Inventory"])
def list_products(current=Depends(get_current_user), db: Session = Depends(get_db)):
    products = db.query(Product).filter(Product.user_id == current["sub"]).all()
    return [{"id": p.id, "name": p.name, "price": p.price,
             "quantity": p.quantity, "unit": p.unit, "threshold": p.threshold,
             "status": "out" if p.quantity == 0 else ("low" if p.quantity <= p.threshold else "ok")}
            for p in products]


@app.post("/products", tags=["Inventory"])
def add_product(data: ProductIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    p = Product(user_id=current["sub"], name=data.name, price=data.price,
                quantity=data.quantity, unit=data.unit, threshold=data.threshold)
    db.add(p); db.commit(); db.refresh(p)
    return {"id": p.id, "name": p.name, "price": p.price,
            "quantity": p.quantity, "unit": p.unit, "threshold": p.threshold}


@app.patch("/products/{pid}/restock", tags=["Inventory"])
def restock(pid: int, data: RestockIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == pid, Product.user_id == current["sub"]).first()
    if not p: raise HTTPException(404, "Product not found")
    if data.quantity <= 0: raise HTTPException(400, "Quantity must be positive")
    p.quantity += data.quantity
    db.commit()
    return {"id": p.id, "name": p.name, "quantity": p.quantity}


# ══════════════════════════════════════════════════════════════════════════════
# SALES ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/sales", tags=["Sales"])
def list_sales(current=Depends(get_current_user), db: Session = Depends(get_db)):
    sales = db.query(Sale).filter(Sale.user_id == current["sub"]).order_by(Sale.date.desc()).all()
    return [{"id": s.id, "product_id": s.product_id, "customer_id": s.customer_id,
             "quantity": s.quantity, "amount": s.amount, "type": s.type, "date": str(s.date)}
            for s in sales]


@app.post("/sales", tags=["Sales"])
def record_sale(data: SaleIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == data.product_id,
                                  Product.user_id == current["sub"]).first()
    if not p: raise HTTPException(404, "Product not found")
    if p.quantity < data.quantity:
        raise HTTPException(400, f"Insufficient stock. Available: {p.quantity} {p.unit}")
    if data.type == "credit" and not data.customer_id:
        raise HTTPException(400, "Customer required for credit sale")

    amount    = p.price * data.quantity
    sale_date = parse_date(data.date)
    sale = Sale(user_id=current["sub"], product_id=data.product_id,
                quantity=data.quantity, type=data.type,
                customer_id=data.customer_id, amount=amount, date=sale_date)
    db.add(sale)
    p.quantity -= data.quantity

    if data.type == "credit":
        txn = Transaction(user_id=current["sub"], customer_id=data.customer_id,
                          amount=amount, type="credit",
                          note=f"Sale: {p.name} x{data.quantity}", date=sale_date)
        db.add(txn)

    db.commit(); db.refresh(sale)
    return {"id": sale.id, "amount": amount,
            "product_name": p.name, "remaining_stock": p.quantity}


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/dashboard", tags=["Dashboard"])
def dashboard(current=Depends(get_current_user), db: Session = Depends(get_db)):
    uid       = current["sub"]
    today_str = date.today()
    txns      = db.query(Transaction).filter(Transaction.user_id == uid).all()
    sales     = db.query(Sale).filter(Sale.user_id == uid).all()
    products  = db.query(Product).filter(Product.user_id == uid).all()
    customers = db.query(Customer).filter(Customer.user_id == uid).all()

    total_credit    = sum(t.amount for t in txns if t.type == "credit")
    total_collected = sum(t.amount for t in txns if t.type == "payment")
    today_sales     = sum(s.amount for s in sales if s.date == today_str)
    low_stock       = [{"id": p.id, "name": p.name, "quantity": p.quantity, "unit": p.unit}
                       for p in products if p.quantity <= p.threshold]

    overdue = []
    for c in customers:
        ctxns   = [t for t in txns if t.customer_id == c.id]
        balance = sum(t.amount if t.type == "credit" else -t.amount for t in ctxns)
        if balance > 0:
            last_credit = max((t.date for t in ctxns if t.type == "credit"), default=None)
            days = (date.today() - last_credit).days if last_credit else 0
            if days >= 10:
                overdue.append({"id": c.id, "name": c.name,
                                "balance": round(balance, 2), "days_overdue": days})

    weekly = []
    for i in range(6, -1, -1):
        day  = date.today() - timedelta(days=i)
        cash = sum(s.amount for s in sales if s.date == day and s.type == "cash")
        cred = sum(s.amount for s in sales if s.date == day and s.type == "credit")
        weekly.append({"date": str(day), "day": day.strftime("%a"), "cash": cash, "credit": cred})

    return {
        "total_credit":    round(total_credit, 2),
        "total_collected": round(total_collected, 2),
        "total_pending":   round(total_credit - total_collected, 2),
        "today_sales":     round(today_sales, 2),
        "low_stock_count": len(low_stock),
        "overdue_count":   len(overdue),
        "low_stock":       low_stock,
        "overdue":         overdue,
        "weekly_sales":    weekly,
    }


# ══════════════════════════════════════════════════════════════════════════════
# REMINDERS
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/reminders", tags=["Reminders"])
def reminders(current=Depends(get_current_user), db: Session = Depends(get_db)):
    uid       = current["sub"]
    customers = db.query(Customer).filter(Customer.user_id == uid).all()
    txns      = db.query(Transaction).filter(Transaction.user_id == uid).all()
    result    = []
    for c in customers:
        ctxns   = [t for t in txns if t.customer_id == c.id]
        balance = sum(t.amount if t.type == "credit" else -t.amount for t in ctxns)
        if balance > 0:
            last_credit = max((t.date for t in ctxns if t.type == "credit"), default=None)
            days = (date.today() - last_credit).days if last_credit else 0
            result.append({
                "id": c.id, "name": c.name, "phone": c.phone,
                "email": c.email or "",
                "balance": round(balance, 2),
                "days_since_credit": days,
                "last_credit_date": str(last_credit) if last_credit else None,
                "urgency": "critical" if days > 30 else ("overdue" if days >= 10 else "recent")
            })
    return sorted(result, key=lambda x: -x["days_since_credit"])


# ══════════════════════════════════════════════════════════════════════════════
# FRONTEND SERVING
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/", include_in_schema=False)
async def serve_frontend():
    return FileResponse("index.html")

@app.get("/logo.png", include_in_schema=False)
async def serve_logo():
    return FileResponse("logo.png")

# ─── HEALTH ───────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
def health():
    email_ok = GMAIL_USER != "YOUR_GMAIL@gmail.com"
    return {
        "status":           "ok",
        "message":          "HisabKitab API v3 is running",
        "email_configured": email_ok,
        "email_account":    GMAIL_USER if email_ok else "⚠️ Not configured yet"
    }
    
