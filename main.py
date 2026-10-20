import os, uuid, calendar, datetime as dt
from typing import Optional, Literal
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt, jwt
# from dotenv import load_dotenv
# load_dotenv()

db = AsyncIOMotorClient(os.environ["MONGO_URI"])[os.getenv("DB_NAME", "jewellery")]
SECRET = os.environ["JWT_SECRET"]
app = FastAPI(title="Jewellery Schemes API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
bearer = HTTPBearer()

def make_token(sub, role):
    return jwt.encode({"sub": sub, "role": role,
        "exp": dt.datetime.utcnow() + dt.timedelta(days=30)}, SECRET, "HS256")

def payload(c: HTTPAuthorizationCredentials = Depends(bearer)):
    try: return jwt.decode(c.credentials, SECRET, ["HS256"])
    except Exception: raise HTTPException(401, "Invalid or expired token")

def admin(p=Depends(payload)):
    if p["role"] != "admin": raise HTTPException(403, "Admin only")

async def customer(p=Depends(payload)):
    u = await db.customers.find_one({"phone": p["sub"], "active": True})
    if p["role"] != "customer" or not u: raise HTTPException(401, "Not allowed")
    return u

def add_months(d: dt.date, n: int):
    m = d.month - 1 + n; y = d.year + m // 12; m = m % 12 + 1
    return dt.date(y, m, min(d.day, calendar.monthrange(y, m)[1]))

class Login(BaseModel): phone: str; password: str
class CustomerIn(BaseModel): name: str; phone: str; password: str
class BachatIn(BaseModel):
    phone: str; emi: float; months: int; start_date: dt.date
class PayIn(BaseModel):
    phone: str; account_id: str; month_no: int; amount: Optional[float] = None
    date: dt.date = None; mode: str = "Cash"; note: str = ""
class SipJoin(BaseModel): phone: str; start_date: dt.date
class SipTx(BaseModel):
    phone: str; account_id: str; type: Literal["deposit", "deduction", "delivery"]
    date: dt.date = None; amount: float = 0          # deposit amount
    amount_deducted: float = 0; grams: float = 0     # deduction / delivery
    note: str = ""

# ---------- auth ----------
@app.post("/auth/login")
async def login(b: Login):
    u = await db.customers.find_one({"phone": b.phone, "active": True})
    if not u or not bcrypt.checkpw(b.password.encode(), u["pwd"]):
        raise HTTPException(401, "Invalid phone or password")
    return {"token": make_token(b.phone, "customer"), "name": u["name"], "phone": u["phone"]}

@app.post("/admin/login")
async def admin_login(b: Login):
    if b.phone != os.environ["ADMIN_USER"] or b.password != os.environ["ADMIN_PASS"]:
        raise HTTPException(401, "Invalid admin credentials")
    return {"token": make_token("admin", "admin")}

# ---------- helpers ----------
def new_id(prefix): return prefix + uuid.uuid4().hex[:6].upper()

def pick(u, key, aid):
    for a in u.get(key) or []:
        if a["id"] == aid: return a
    raise HTTPException(404, "Account not found")

def bachat_view(b):
    start = dt.date.fromisoformat(b["start_date"])
    paid = {p["month_no"]: p for p in b["payments"]}
    today, rows = dt.date.today(), []
    for i in range(1, b["months"] + 1):
        due = add_months(start, i - 1)
        if i == b["months"]: st = "bonus"
        elif i in paid: st = "paid"
        else: st = "overdue" if due < today.replace(day=1) else "pending"
        p = paid.get(i, {})
        rows.append({"month_no": i, "month": due.strftime("%b %Y"), "status": st,
            "amount": p.get("amount", 0 if st == "bonus" else b["emi"]),
            "paid_on": p.get("date"), "mode": p.get("mode"), "note": p.get("note", "")})
    return {"id": b["id"], "emi": b["emi"], "months": b["months"], "start_date": b["start_date"],
        "maturity_month": add_months(start, b["months"] - 1).strftime("%b %Y"),
        "emis_to_pay": b["months"] - 1, "total_paid": sum(p["amount"] for p in b["payments"]),
        "jewellery_value": b["emi"] * b["months"], "installments": rows}

def sip_summary(s):
    dep = sum(t["amount"] for t in s["txs"] if t["type"] == "deposit")
    ded = sum(t["amount_deducted"] for t in s["txs"] if t["type"] == "deduction")
    bought = sum(t["grams"] for t in s["txs"] if t["type"] == "deduction")
    out = sum(t["grams"] for t in s["txs"] if t["type"] == "delivery")
    return dep, ded, round(bought - out, 3)

def sip_view(s):
    dep, ded, grams = sip_summary(s)
    return {"id": s["id"], "start_date": s["start_date"], "total_deposited": dep,
        "total_deducted": ded, "cash_balance": dep - ded, "gold_grams": grams,
        "transactions": sorted(s["txs"], key=lambda t: t["date"], reverse=True)}

# ---------- customer endpoints ----------
@app.get("/me")
async def me(u=Depends(customer)):
    return {"name": u["name"], "phone": u["phone"],
            "bachat": len(u.get("bachat") or []), "sip": len(u.get("sip") or [])}

@app.get("/me/bachat")
async def my_bachat(u=Depends(customer)):
    return {"accounts": [bachat_view(b) for b in u.get("bachat") or []]}

@app.get("/me/sip")
async def my_sip(u=Depends(customer)):
    return {"accounts": [sip_view(s) for s in u.get("sip") or []]}

# ---------- admin endpoints (for the admin website) ----------
async def get_cust(phone):
    u = await db.customers.find_one({"phone": phone})
    if not u: raise HTTPException(404, "Customer not found")
    return u

@app.post("/admin/customers", dependencies=[Depends(admin)])
async def add_customer(b: CustomerIn):
    if await db.customers.find_one({"phone": b.phone}): raise HTTPException(409, "Phone exists")
    await db.customers.insert_one({"name": b.name, "phone": b.phone, "active": True,
        "pwd": bcrypt.hashpw(b.password.encode(), bcrypt.gensalt()), "bachat": [], "sip": []})
    return {"ok": True}

@app.get("/admin/customers", dependencies=[Depends(admin)])
async def list_customers():
    return [{"name": c["name"], "phone": c["phone"], "active": c["active"],
             "bachat": len(c.get("bachat") or []), "sip": len(c.get("sip") or [])}
            async for c in db.customers.find()]

@app.get("/admin/customers/{phone}", dependencies=[Depends(admin)])
async def customer_detail(phone: str):
    u = await get_cust(phone)
    return {"name": u["name"], "phone": u["phone"], "active": u["active"],
            "bachat": [bachat_view(b) for b in u.get("bachat") or []],
            "sip": [sip_view(s) for s in u.get("sip") or []]}

@app.post("/admin/customers/{phone}/reset-password", dependencies=[Depends(admin)])
async def reset_pw(phone: str, b: Login):
    await get_cust(phone)
    await db.customers.update_one({"phone": phone},
        {"$set": {"pwd": bcrypt.hashpw(b.password.encode(), bcrypt.gensalt())}})
    return {"ok": True}

@app.post("/admin/bachat/enroll", dependencies=[Depends(admin)])
async def bachat_enroll(b: BachatIn):
    await get_cust(b.phone)
    if b.months < 2 or b.emi <= 0: raise HTTPException(400, "Invalid EMI/months")
    acc = {"id": new_id("BY"), "emi": b.emi, "months": b.months,
           "start_date": b.start_date.isoformat(), "payments": []}
    await db.customers.update_one({"phone": b.phone}, {"$push": {"bachat": acc}})
    return {"ok": True, "account_id": acc["id"]}

@app.post("/admin/bachat/payment", dependencies=[Depends(admin)])
async def bachat_pay(b: PayIn):
    u = await get_cust(b.phone); bc = pick(u, "bachat", b.account_id)
    if not 1 <= b.month_no < bc["months"]: raise HTTPException(400, "Invalid month (last month is bonus)")
    if any(p["month_no"] == b.month_no for p in bc["payments"]): raise HTTPException(409, "Already paid")
    rec = {"month_no": b.month_no, "amount": b.amount or bc["emi"],
           "date": (b.date or dt.date.today()).isoformat(), "mode": b.mode, "note": b.note}
    await db.customers.update_one({"phone": b.phone, "bachat.id": b.account_id},
                                  {"$push": {"bachat.$.payments": rec}})
    return {"ok": True}

@app.post("/admin/sip/enroll", dependencies=[Depends(admin)])
async def sip_enroll(b: SipJoin):
    await get_cust(b.phone)
    acc = {"id": new_id("SP"), "start_date": b.start_date.isoformat(), "txs": []}
    await db.customers.update_one({"phone": b.phone}, {"$push": {"sip": acc}})
    return {"ok": True, "account_id": acc["id"]}

@app.post("/admin/sip/transaction", dependencies=[Depends(admin)])
async def sip_tx(b: SipTx):
    u = await get_cust(b.phone); s = pick(u, "sip", b.account_id)
    dep, ded, grams = sip_summary(s)
    if b.type == "deposit" and b.amount <= 0: raise HTTPException(400, "Amount required")
    if b.type == "deduction":
        if b.grams <= 0 or b.amount_deducted <= 0: raise HTTPException(400, "grams & amount_deducted required")
        if b.amount_deducted > dep - ded: raise HTTPException(400, "Insufficient balance")
    if b.type == "delivery" and (b.grams <= 0 or b.grams > grams):
        raise HTTPException(400, "Invalid grams (exceeds gold in account)")
    rec = {"type": b.type, "date": (b.date or dt.date.today()).isoformat(), "amount": b.amount,
           "amount_deducted": b.amount_deducted, "grams": b.grams, "note": b.note}
    await db.customers.update_one({"phone": b.phone, "sip.id": b.account_id},
                                  {"$push": {"sip.$.txs": rec}})
    return {"ok": True}
