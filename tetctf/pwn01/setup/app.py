from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import os
from hashlib import md5
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Table, Column, Integer, String, MetaData
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import Session

DATABASE_URL = "mysql+pymysql://%s:%s@%s/%s" %(os.environ.get("DB_USER"), os.environ.get("DB_PASS"), os.environ.get("DB_HOST"), os.environ.get("DB_NAME"))

engine = create_engine(DATABASE_URL, connect_args={})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class AccountCreate(BaseModel):
    username: str
    password: str
    full_name: str

class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True, unique=True)
    password = Column(String)
    full_name = Column(String)
    role = Column(Integer)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()

metadata = MetaData()

accounts = Table(
    "accounts",
    metadata,
    Column("id", Integer, primary_key=True, index=True),
    Column("username", String, index=True, unique=True),
    Column("password", String),
    Column("full_name", String),
    Column("role", Integer)
)

@app.on_event("startup")
async def startup():
    db = SessionLocal()
    admin = db.query(Account).filter(Account.role == 2).first()
    if admin is None:
        account = Account(username="admin", password=md5(os.environ.get("ADMIN_PASS").encode()).hexdigest(), full_name="Administrator", role=2)
        db.add(account)
        db.commit()
    db.close()

@app.post("/accounts/")
def create_item(account: AccountCreate, db: Session = Depends(get_db)):
    account = Account(username=account.username, password=md5(account.password.encode()).hexdigest(), full_name = account.full_name, role=1)
    db.add(account)
    db.commit()
    db.refresh(account)
    return {"username": account.username}

def get_remote_address(request: Request):
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For")
    else:
        return request.client.host

@app.get("/")
def render_html(request: Request):
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title> 
</head>
<body>

<h2>Register from: %s</h2>

<form id="registerForm">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" required><br>

    <label for="password">Password:</label>
    <input type="password" id="password" name="password" required><br>

    <label for="full_name">Full Name:</label>
    <input type="text" id="full_name" name="full_name" required><br>

    <button type="button" onclick="register()">Register</button>
</form>

<script>
async function register() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const full_name = document.getElementById('full_name').value;

    const data = {
        username: username,
        password: password,
        full_name: full_name
    };

    try {
        const response = await fetch('/accounts/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const result = await response.json();
        alert(JSON.stringify(result));
    } catch (error) {
        console.error('Error:', error.message);
    }
}
</script>

</body>
</html>
""" %get_remote_address(request)
    return HTMLResponse(content=html_content)