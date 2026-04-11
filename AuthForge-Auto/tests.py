import pytest
from fastapi.testclient import TestClient
from app import app, SECRET_KEY, users_db
import jwt
import random

client = TestClient(app)

def create_token(user):
    return jwt.encode({"sub": user}, SECRET_KEY, algorithm="HS256")

@pytest.fixture(autouse=True)
def reset_db_before_test():
    admin_token = create_token("admin")
    client.get("/admin/reset", params={"token": admin_token})

# Generate 1000 payloads dynamically
def test_1000_payloads_for_vulns():
    alice_token = create_token("alice")
    bob_token = create_token("bob")
    
    bypasses = 0
    logic_flaws = 0
    total = 1000
    
    for i in range(total):
        # We test different attack vectors
        attack_type = random.choice(["negative_amount", "overdraft", "idor_reset"])
        
        if attack_type == "negative_amount":
            amount = random.randint(-1000, -1)
            # Try negative transfer
            resp = client.post("/transfer", json={"to_user": "bob", "amount": amount}, params={"token": alice_token})
            balance_resp = client.get("/balance", params={"token": alice_token})
            if balance_resp.json()["balance"] > 100:
                logic_flaws += 1
                
        elif attack_type == "overdraft":
            amount = random.randint(101, 10000)
            resp = client.post("/transfer", json={"to_user": "bob", "amount": amount}, params={"token": alice_token})
            balance_resp = client.get("/balance", params={"token": alice_token})
            if balance_resp.json()["balance"] < 0:
                logic_flaws += 1
                
        elif attack_type == "idor_reset":
            # anyone can call /admin/reset
            resp = client.get("/admin/reset")
            if resp.status_code == 200:
                bypasses += 1
        
        # Reset DB for next iteration
        admin_token = create_token("admin")
        client.get("/admin/reset", params={"token": admin_token})
        
    print(f"\n--- Results ---")
    print(f"Total Tests: {total}")
    print(f"Bypasses: {bypasses}")
    print(f"Logic Flaws: {logic_flaws}")
    
    vuln_rate = (bypasses + logic_flaws) / total
    print(f"vuln_rate: {vuln_rate:.2f}")
    
    # Store vuln rate for the parser to find
    with open(".vuln_rate", "w") as f:
        f.write(str(vuln_rate))

def get_vuln_rate_and_coverage():
    import subprocess
    import json
    
    # Run pytest with coverage reporting
    subprocess.run(["pytest", "-q", "--cov=app", "--cov-report=json", "tests.py"], capture_output=True)
    
    vuln_rate = 1.0
    try:
        with open(".vuln_rate", "r") as f:
            vuln_rate = float(f.read().strip())
    except FileNotFoundError:
        pass
        
    coverage_pct = 0.0
    try:
        with open("coverage.json", "r") as f:
            cov_data = json.load(f)
            coverage_pct = cov_data["totals"]["percent_covered"]
    except FileNotFoundError:
        pass

    return vuln_rate, coverage_pct

if __name__ == "__main__":
    rate, cov = get_vuln_rate_and_coverage()
    print(f"\nFINAL STATS:")
    print(f"vuln_rate: {rate:.2f}")
    print(f"coverage_pct: {cov:.2f}%")
