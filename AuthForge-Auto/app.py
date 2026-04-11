from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
import jwt

app = FastAPI()
SECRET_KEY = "supersecret"

users_db = {"alice": 100, "bob": 100}

class TransferRequest(BaseModel):
    to_user: str
    amount: int

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload["sub"]
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/transfer")
def transfer(req: TransferRequest, token: str):
    user = verify_token(token)
    if user not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    # Vulnerability 1 patched
    if users_db.get(user, 0) < req.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")
    
    users_db[user] -= req.amount
    
    if req.to_user not in users_db:
        users_db[req.to_user] = 0
    users_db[req.to_user] += req.amount
    
    return {"msg": "Transfer successful"}

@app.get("/balance")
def get_balance(token: str):
    user = verify_token(token)
    return {"balance": users_db.get(user, 0)}

@app.get("/admin/reset")
def reset_db(token: str = None):
    # Fixed IDOR / Missing RBAC
    if not token or verify_token(token) != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    global users_db
    users_db = {"alice": 100, "bob": 100}
    return {"msg": "DB Reset"}
