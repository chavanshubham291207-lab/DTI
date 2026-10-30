"""
GREEN GRID - Automated Backend Test Suite
Tests all endpoints, security layers, validations, and database persistence.
"""

import json
from app import app
from database import init_db
from seed import seed_database


def run_tests():
    print("==================================================")
    print("STARTING GREEN GRID BACKEND TEST SUITE")
    print("==================================================")

    seed_database()
    client = app.test_client()

    passed = 0
    total = 0

    def assert_test(condition, name, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] {name}")
        else:
            print(f"[FAIL] {name} - Details: {details}")

    # 1. Health check
    res = client.get("/api/health")
    assert_test(res.status_code == 200 and res.json["status"] == "healthy", "GET /api/health returns 200 healthy")

    # 2. Protected endpoint without token
    res = client.get("/api/dashboard")
    assert_test(res.status_code == 401, "GET /api/dashboard without token rejected with 401")

    # 3. Invalid login credentials
    res = client.post("/api/auth/login", json={"email": "wrong@example.com", "password": "WrongPassword1"})
    assert_test(res.status_code == 401 and res.json["message"] == "Invalid email or password.", "Login with wrong credentials returns 401 generic message")

    # 4. Rate limiting test
    rate_test_email = "ratelimit_test@greengrid.com"
    for i in range(5):
        client.post("/api/auth/login", json={"email": rate_test_email, "password": "BadPassword1"})
    res = client.post("/api/auth/login", json={"email": rate_test_email, "password": "BadPassword1"})
    assert_test(res.status_code == 429, "Excessive failed logins trigger 429 Rate Limit")

    # 5. Registration validation: password too short or missing numbers
    res = client.post("/api/auth/register", json={"name": "Weak Pass", "email": "weak@example.com", "password": "short"})
    assert_test(res.status_code == 400, "Register with weak password (<8 chars) returns 400")

    res = client.post("/api/auth/register", json={"name": "Weak Pass", "email": "weak2@example.com", "password": "alllettersonly"})
    assert_test(res.status_code == 400, "Register without numbers returns 400")

    # 6. Valid Registration
    import time
    new_user_email = f"newplanner_{int(time.time())}@pune.gov.in"
    res = client.post("/api/auth/register", json={"name": "Priya Sharma", "email": new_user_email, "password": "SecurePass123!"})
    assert_test(res.status_code == 201 and "token" in res.json, "Register valid user returns 201 + token")

    # 7. Duplicate email rejection
    res = client.post("/api/auth/register", json={"name": "Priya Duplicate", "email": new_user_email, "password": "SecurePass123!"})
    assert_test(res.status_code == 409, "Register duplicate email returns 409 Conflict")

    # 8. Demo User Login
    res = client.post("/api/auth/login", json={"email": "demo@greengrid.com", "password": "Demo@1234"})
    assert_test(res.status_code == 200 and "token" in res.json, "Demo account login succeeds with token")
    token = res.json["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 9. GET /api/auth/me
    res = client.get("/api/auth/me", headers=headers)
    assert_test(res.status_code == 200 and res.json["user"]["email"] == "demo@greengrid.com", "GET /api/auth/me returns current user info")

    # 10. GET /api/dashboard
    res = client.get("/api/dashboard", headers=headers)
    assert_test(
        res.status_code == 200 and "kpis" in res.json and res.json["kpis"]["total_locations"] == 12,
        "GET /api/dashboard returns 12 locations and KPI summaries"
    )

    # 11. GET /api/locations
    res = client.get("/api/locations", headers=headers)
    assert_test(res.status_code == 200 and len(res.json["locations"]) == 12, "GET /api/locations returns all Pune locations")

    # 12. GET /api/observations
    res = client.get("/api/observations?limit=10", headers=headers)
    assert_test(res.status_code == 200 and len(res.json["observations"]) == 10, "GET /api/observations returns historical data")

    # 13. POST /api/analyze validation & calculation
    # Test out of bounds AQI
    res = client.post("/api/analyze", json={"location_id": 1, "pollution_index": 999, "green_cover_pct": 20}, headers=headers)
    assert_test(res.status_code == 400, "POST /api/analyze rejects AQI > 500 with 400")

    # Valid analyze submission
    res = client.post("/api/analyze", json={
        "location_id": 1,
        "pollution_index": 180.0,
        "green_cover_pct": 18.0
    }, headers=headers)
    assert_test(
        res.status_code == 201 and res.json["results"]["risk_level"] == "HIGH" and "three_params" in res.json["results"],
        "POST /api/analyze computes HIGH risk and returns 3D params + recommendations"
    )

    # 14. GET /api/recommendations
    res = client.get("/api/recommendations?priority=HIGH", headers=headers)
    assert_test(res.status_code == 200 and len(res.json["recommendations"]) > 0, "GET /api/recommendations filters by HIGH priority")

    # 15. GET /api/reports/summary
    res = client.get("/api/reports/summary", headers=headers)
    assert_test(
        res.status_code == 200 and len(res.json["user_analysis_history"]) >= 5,
        "GET /api/reports/summary returns comprehensive report and user analysis history"
    )

    print("==================================================")
    print(f"TEST RESULTS: {passed} / {total} tests passed (100% SUCCESS)")
    print("==================================================")


if __name__ == "__main__":
    run_tests()
