from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine, Column, Integer, String, Float, Enum, Date, ForeignKey
from sqlalchemy.orm import sessionmaker, Session, relationship, declarative_base
from pydantic import BaseModel
from typing import Optional
from datetime import date, datetime, timedelta
import hashlib, hmac, json, base64, os, enum

# ─── APP ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="HisabKitab API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-in-production-123")
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
    _tablename_ = "users"
    id        = Column(Integer, primary_key=True, index=True)
    name      = Column(String, nullable=False)
    email     = Column(String, unique=True, index=True, nullable=False)
    password  = Column(String, nullable=False)
    shop_name = Column(String, default="My Dukaan")
    phone     = Column(String, default="")   # ✅ NEW: owner WhatsApp number

class Customer(Base):
    _tablename_ = "customers"
    id           = Column(Integer, primary_key=True, index=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False)
    name         = Column(String, nullable=False)
    phone        = Column(String, nullable=False)
    address      = Column(String, default="")
    created_at   = Column(Date, default=date.today)
    transactions = relationship("Transaction", back_populates="customer")

class TransactionType(str, enum.Enum):
    credit  = "credit"
    payment = "payment"

class Transaction(Base):
    _tablename_ = "transactions"
    id          = Column(Integer, primary_key=True, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount      = Column(Float, nullable=False)
    type        = Column(Enum(TransactionType), nullable=False)
    note        = Column(String, default="")
    date        = Column(Date, default=date.today)
    customer    = relationship("Customer", back_populates="transactions")

class Product(Base):
    _tablename_ = "products"
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
    _tablename_ = "sales"
    id          = Column(Integer, primary_key=True, index=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False)
    product_id  = Column(Integer, ForeignKey("products.id"), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=True)
    quantity    = Column(Integer, nullable=False)
    amount      = Column(Float, nullable=False)
    type        = Column(Enum(SaleType), nullable=False)
    date        = Column(Date, default=date.today)

# ✅ This creates the phone column automatically if it doesn't exist yet
Base.metadata.create_all(bind=engine)

# Add phone column to existing database if upgrading from old version
try:
    with engine.connect() as conn:
        conn.execute(_import_('sqlalchemy').text("ALTER TABLE users ADD COLUMN phone VARCHAR DEFAULT ''"))
        conn.commit()
except Exception:
    pass  # Column already exists, no problem

# ─── DATE HELPER ──────────────────────────────────────────────────────────────
def parse_date(raw: Optional[str]) -> date:
    """Safely parse any date string → Python date. Never crashes."""
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
    phone: str = ""          # ✅ NEW: owner WhatsApp number e.g. "+919876543210"

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

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
@app.post("/auth/register", tags=["Auth"])
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(
        name      = data.name,
        email     = data.email,
        password  = hash_password(data.password),
        shop_name = data.shop_name,
        phone     = data.phone   # ✅ save owner phone
    )
    db.add(user); db.commit(); db.refresh(user)
    return {"message": "Registered successfully", "user_id": user.id}

@app.post("/auth/login", tags=["Auth"])
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email == data.email,
        User.password == hash_password(data.password)
    ).first()
    if not user:
        raise HTTPException(401, "Invalid email or password")
    exp   = (datetime.utcnow() + timedelta(days=7)).timestamp()
    token = make_token({"sub": user.id, "email": user.email, "exp": exp})
    return {
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "shop_name": user.shop_name,
            "phone": user.phone or ""   # ✅ return phone to frontend
        }
    }

@app.get("/auth/me", tags=["Auth"])
def me(current=Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == current["sub"]).first()
    return {
        "id": user.id, "name": user.name,
        "email": user.email, "shop_name": user.shop_name,
        "phone": user.phone or ""
    }

# ✅ NEW: Forgot Password — check if email exists
@app.post("/auth/forgot-password", tags=["Auth"])
def forgot_password(data: ForgotPasswordIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        return {"exists": False}
    return {"exists": True, "name": user.name}

# ✅ NEW: Reset Password — set new password directly
@app.post("/auth/reset-password", tags=["Auth"])
def reset_password(data: ResetPasswordIn, db: Session = Depends(get_db)):
    if len(data.new_password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(404, "No account found with this email")
    user.password = hash_password(data.new_password)
    db.commit()
    return {"message": "Password reset successfully"}

# ─── CUSTOMER ROUTES ──────────────────────────────────────────────────────────
@app.get("/customers", tags=["Customers"])
def list_customers(current=Depends(get_current_user), db: Session = Depends(get_db)):
    customers = db.query(Customer).filter(Customer.user_id == current["sub"]).all()
    result = []
    for c in customers:
        txns    = db.query(Transaction).filter(Transaction.customer_id == c.id).all()
        balance = sum(t.amount if t.type == "credit" else -t.amount for t in txns)
        result.append({
            "id": c.id, "name": c.name, "phone": c.phone,
            "address": c.address, "created_at": str(c.created_at),
            "balance": round(balance, 2)
        })
    return result

@app.post("/customers", tags=["Customers"])
def add_customer(data: CustomerIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    c = Customer(user_id=current["sub"], name=data.name, phone=data.phone, address=data.address)
    db.add(c); db.commit(); db.refresh(c)
    return {"id": c.id, "name": c.name, "phone": c.phone, "address": c.address, "balance": 0}

@app.get("/customers/{cid}", tags=["Customers"])
def get_customer(cid: int, current=Depends(get_current_user), db: Session = Depends(get_db)):
    c = db.query(Customer).filter(Customer.id == cid, Customer.user_id == current["sub"]).first()
    if not c:
        raise HTTPException(404, "Customer not found")
    txns    = db.query(Transaction).filter(Transaction.customer_id == cid).order_by(Transaction.date).all()
    balance = 0
    ledger  = []
    for t in txns:
        balance += t.amount if t.type == "credit" else -t.amount
        ledger.append({
            "id": t.id, "amount": t.amount, "type": t.type,
            "note": t.note, "date": str(t.date),
            "running_balance": round(balance, 2)
        })
    return {
        "id": c.id, "name": c.name, "phone": c.phone,
        "address": c.address, "balance": round(balance, 2),
        "transactions": ledger
    }

# ─── TRANSACTION ROUTES ───────────────────────────────────────────────────────
@app.post("/transactions", tags=["Udhaar"])
def add_transaction(data: TransactionIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    c = db.query(Customer).filter(
        Customer.id == data.customer_id, Customer.user_id == current["sub"]
    ).first()
    if not c:
        raise HTTPException(404, "Customer not found")

    # Block overpayment
    if data.type == "payment":
        txns    = db.query(Transaction).filter(Transaction.customer_id == data.customer_id).all()
        balance = sum(t.amount if t.type == "credit" else -t.amount for t in txns)
        if data.amount > balance:
            raise HTTPException(400, f"Payment ₹{data.amount} exceeds balance ₹{round(balance,2)}")

    t = Transaction(
        user_id     = current["sub"],
        customer_id = data.customer_id,
        amount      = data.amount,
        type        = data.type,
        note        = data.note,
        date        = parse_date(data.date)
    )
    db.add(t); db.commit(); db.refresh(t)
    return {"id": t.id, "amount": t.amount, "type": t.type, "note": t.note, "date": str(t.date)}

# ─── INVENTORY ROUTES ─────────────────────────────────────────────────────────
@app.get("/products", tags=["Inventory"])
def list_products(current=Depends(get_current_user), db: Session = Depends(get_db)):
    products = db.query(Product).filter(Product.user_id == current["sub"]).all()
    return [{
        "id": p.id, "name": p.name, "price": p.price,
        "quantity": p.quantity, "unit": p.unit, "threshold": p.threshold,
        "status": "out" if p.quantity == 0 else ("low" if p.quantity <= p.threshold else "ok")
    } for p in products]

@app.post("/products", tags=["Inventory"])
def add_product(data: ProductIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    p = Product(
        user_id=current["sub"], name=data.name, price=data.price,
        quantity=data.quantity, unit=data.unit, threshold=data.threshold
    )
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

# ─── SALES ROUTES ─────────────────────────────────────────────────────────────
@app.get("/sales", tags=["Sales"])
def list_sales(current=Depends(get_current_user), db: Session = Depends(get_db)):
    sales = db.query(Sale).filter(Sale.user_id == current["sub"]).order_by(Sale.date.desc()).all()
    return [{
        "id": s.id, "product_id": s.product_id, "customer_id": s.customer_id,
        "quantity": s.quantity, "amount": s.amount, "type": s.type, "date": str(s.date)
    } for s in sales]

@app.post("/sales", tags=["Sales"])
def record_sale(data: SaleIn, current=Depends(get_current_user), db: Session = Depends(get_db)):
    p = db.query(Product).filter(Product.id == data.product_id, Product.user_id == current["sub"]).first()
    if not p: raise HTTPException(404, "Product not found")
    if p.quantity < data.quantity:
        raise HTTPException(400, f"Insufficient stock. Available: {p.quantity} {p.unit}")
    if data.type == "credit" and not data.customer_id:
        raise HTTPException(400, "Customer required for credit sale")

    amount    = p.price * data.quantity
    sale_date = parse_date(data.date)

    sale = Sale(
        user_id=current["sub"], product_id=data.product_id,
        quantity=data.quantity, type=data.type,
        customer_id=data.customer_id, amount=amount, date=sale_date
    )
    db.add(sale)
    p.quantity -= data.quantity  # deduct stock

    # ✅ Auto-create udhaar transaction for credit sale
    if data.type == "credit":
        txn = Transaction(
            user_id=current["sub"], customer_id=data.customer_id,
            amount=amount, type="credit",
            note=f"Sale: {p.name} x{data.quantity}", date=sale_date
        )
        db.add(txn)

    db.commit(); db.refresh(sale)
    return {"id": sale.id, "amount": amount, "product_name": p.name, "remaining_stock": p.quantity}

# ─── DASHBOARD ────────────────────────────────────────────────────────────────
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
                overdue.append({"id": c.id, "name": c.name, "balance": round(balance, 2), "days_overdue": days})

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

# ─── REMINDERS ────────────────────────────────────────────────────────────────
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
                "balance": round(balance, 2),
                "days_since_credit": days,
                "last_credit_date": str(last_credit) if last_credit else None,
                "urgency": "critical" if days > 30 else ("overdue" if days >= 10 else "recent")
            })
    return sorted(result, key=lambda x: -x["days_since_credit"])

# ─── FRONTEND & ASSETS ────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_frontend():
    return FileResponse("index.html")

# ✅ NEW: Serve the logo directly from the main folder
@app.get("/logo.png", include_in_schema=False)
async def serve_logo():
    return FileResponse("logo.png")

# ─── HEALTH ───────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
def health():
    return {
        "status": "ok",
        "message": "HisabKitab API is running"
    }
