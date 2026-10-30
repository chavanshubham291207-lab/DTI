"""
GREEN GRID - Comprehensive API & Authentication Test Suite
Tests authentication, password policy, rate limiting, token security,
and protected endpoint data contracts using a temporary SQLite database.
"""

import os
import tempfile
import sqlite3
import json
import time
import jwt
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Setup temporary database before importing app/database modules
temp_db_fd, temp_db_path = tempfile.mkstemp(suffix=".db", prefix="greengrid_test_")
os.close(temp_db_fd)

import database
database.DB_FILE = Path(temp_db_path)

from app import app
from database import init_db, get_db
from seed import seed_database
import auth
from auth import (
    password_problems,
    create_jwt_token,
    JWT_SECRET,
    FAILED_LOGIN_ATTEMPTS,
)


def run_all_tests():
    print("=" * 65)
    print("RUNNING GREEN GRID AUTH & API TEST SUITE (TEMPORARY DATABASE)")
    print(f"Temporary DB: {temp_db_path}")
    print("=" * 65)

    # Initialize and seed temporary database
    init_db()
    seed_database()

    client = app.test_client()
    passed = 0
    total = 0

    def record_test(condition, test_name, extra_details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"  [PASS] {test_name}")
        else:
            print(f"  [FAIL] {test_name}")
            if extra_details:
                print(f"         Details: {extra_details}")

    # =========================================================================
    # 1. Password Policy Tests - Each rule rejected separately
    # =========================================================================
    print("\n--- 1. Testing Password Policy (Each Rule Rejected Separately) ---")

    rules_test_cases = [
        # (password, rule_name, expected_problem_substring)
        ("Ab1!xyz", "Too short (< 8 chars)", "at least 8 characters"),
        ("A" * 65 + "b1!", "Too long (> 64 chars)", "no more than 64 characters"),
        ("lowercase123!", "No uppercase letter", "uppercase letter"),
        ("UPPERCASE123!", "No lowercase letter", "lowercase letter"),
        ("NoNumberHere!", "No number", "number"),
        ("NoSpecialChar123", "No special character", "special character"),
        ("Has Space 123!A", "Contains spaces", "not contain spaces"),
        ("password123", "Common password (password123)", "common"),
        ("Password@123", "Common password (Password@123)", "common"),
        ("12345678", "Common password (12345678)", "common"),
        ("qwerty123", "Common password (qwerty123)", "common"),
        ("admin@123", "Common password (admin@123)", "common"),
    ]

    for pw, label, problem_sub in rules_test_cases:
        probs = password_problems(pw)
        has_prob = any(problem_sub.lower() in p.lower() for p in probs)

        # Also test via POST /api/auth/register endpoint
        res = client.post(
            "/api/auth/register",
            json={
                "name": "Test User",
                "email": f"test_{total}@example.com",
                "password": pw,
            },
        )
        api_rejected = res.status_code == 400 and "problems" in res.json

        record_test(
            has_prob and api_rejected,
            f"Rule Rejected: {label}",
            f"Problems: {probs}, API Status: {res.status_code}",
        )

    # =========================================================================
    # 2. Strong Password Accepted (201)
    # =========================================================================
    print("\n--- 2. Testing Strong Password Registration (201) ---")
    strong_pw = "Secure#Pune2026!Plan"
    record_test(
        len(password_problems(strong_pw)) == 0,
        "password_problems() returns empty list for strong password",
    )

    reg_res = client.post(
        "/api/auth/register",
        json={
            "name": "Kavita Deshmukh",
            "email": "kavita.deshmukh@punegov.in",
            "password": strong_pw,
        },
    )
    strong_reg_ok = (
        reg_res.status_code == 201
        and "token" in reg_res.json
        and reg_res.json["user"]["email"] == "kavita.deshmukh@punegov.in"
    )
    record_test(strong_reg_ok, "POST /api/auth/register accepts strong password (201)")

    # =========================================================================
    # 3. Duplicate Email Rejection (409) - Case-insensitive
    # =========================================================================
    print("\n--- 3. Testing Duplicate Email Handling (409) ---")
    # Same email exact case
    dup_res1 = client.post(
        "/api/auth/register",
        json={
            "name": "Kavita Copy",
            "email": "kavita.deshmukh@punegov.in",
            "password": strong_pw,
        },
    )
    record_test(dup_res1.status_code == 409, "Duplicate email exact case returns 409")

    # Same email different uppercase/mixed case
    dup_res2 = client.post(
        "/api/auth/register",
        json={
            "name": "Kavita Mixed Case",
            "email": "KAVITA.DESHMUKH@PUNEGOV.IN",
            "password": strong_pw,
        },
    )
    record_test(
        dup_res2.status_code == 409,
        "Duplicate email with different casing returns 409 (case-insensitive)",
    )

    # =========================================================================
    # 4. Login - Generic 401 Message for wrong password & unknown email
    # =========================================================================
    print("\n--- 4. Testing Login 401 Generic Error Message ---")
    # Wrong password for existing user
    res_wrong_pw = client.post(
        "/api/auth/login",
        json={"email": "kavita.deshmukh@punegov.in", "password": "WrongPassword#999"},
    )
    # Unknown email
    res_unknown_email = client.post(
        "/api/auth/login",
        json={"email": "nonexistent_user_99@greengrid.com", "password": strong_pw},
    )

    expected_msg = "Invalid email or password."
    same_status = (
        res_wrong_pw.status_code == 401 and res_unknown_email.status_code == 401
    )
    same_msg = (
        res_wrong_pw.json.get("message") == expected_msg
        and res_unknown_email.json.get("message") == expected_msg
    )
    record_test(
        same_status and same_msg,
        "Wrong password and unknown email return identical 401 message",
        f"Wrong PW Msg: {res_wrong_pw.json}, Unknown Email Msg: {res_unknown_email.json}",
    )

    # =========================================================================
    # 5. Rate Limiting - 6th failed attempt returns 429
    # =========================================================================
    print("\n--- 5. Testing Login Rate Limiting (5 allowed, 6th is 429) ---")
    rate_email = "rate_limit_target@greengrid.com"
    FAILED_LOGIN_ATTEMPTS.pop(rate_email, None)

    for i in range(1, 6):
        r = client.post(
            "/api/auth/login",
            json={"email": rate_email, "password": f"BadPassword#{i}"},
        )
        assert r.status_code == 401, f"Attempt {i} should be 401"

    # 6th attempt must trigger 429
    res_rate_limited = client.post(
        "/api/auth/login",
        json={"email": rate_email, "password": "BadPassword#6"},
    )
    record_test(
        res_rate_limited.status_code == 429
        and "too many" in res_rate_limited.json.get("message", "").lower(),
        "6th consecutive failed login attempt is rejected with 429 Rate Limit",
    )

    # Clean up rate limit state for other tests
    FAILED_LOGIN_ATTEMPTS.pop(rate_email, None)

    # =========================================================================
    # 6. Public vs Protected Endpoints - Missing, Garbage, Expired Tokens
    # =========================================================================
    print("\n--- 6. Testing Token Security on Protected Endpoints ---")

    # /api/health works without a token
    health_res = client.get("/api/health")
    record_test(
        health_res.status_code == 200 and health_res.json.get("status") == "healthy",
        "GET /api/health works without an authorization token",
    )

    protected_endpoints = [
        ("GET", "/api/dashboard"),
        ("GET", "/api/locations"),
        ("GET", "/api/observations"),
        ("POST", "/api/analyze"),
        ("GET", "/api/recommendations"),
        ("GET", "/api/reports/summary"),
        ("GET", "/api/auth/me"),
    ]

    # A. Missing token
    all_missing_rejected = True
    for method, path in protected_endpoints:
        res = client.open(path, method=method)
        if res.status_code != 401:
            all_missing_rejected = False
            print(f"         Missing token allowed on: {method} {path} ({res.status_code})")
    record_test(all_missing_rejected, "Missing token returns 401 on every protected endpoint")

    # B. Garbage token
    garbage_headers = {"Authorization": "Bearer garbage.invalid.token123"}
    all_garbage_rejected = True
    for method, path in protected_endpoints:
        res = client.open(path, method=method, headers=garbage_headers)
        if res.status_code != 401:
            all_garbage_rejected = False
            print(f"         Garbage token allowed on: {method} {path} ({res.status_code})")
    record_test(all_garbage_rejected, "Garbage token returns 401 on every protected endpoint")

    # C. Expired token
    expired_payload = {
        "user_id": 1,
        "email": "demo@greengrid.com",
        "name": "Demo User",
        "role": "user",
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),  # Expired 1 hour ago
        "iat": datetime.now(timezone.utc) - timedelta(hours=3),
    }
    expired_token = jwt.encode(expired_payload, JWT_SECRET, algorithm="HS256")
    expired_headers = {"Authorization": f"Bearer {expired_token}"}

    all_expired_rejected = True
    for method, path in protected_endpoints:
        res = client.open(path, method=method, headers=expired_headers)
        if res.status_code != 401 or "expired" not in res.json.get("message", "").lower():
            all_expired_rejected = False
            print(f"         Expired token not rejected properly on: {method} {path}")
    record_test(all_expired_rejected, "Expired token returns 401 'Session expired' on every protected endpoint")

    # =========================================================================
    # 7. Information Leakage Prevention - Passwords & Hashes Never Appear
    # =========================================================================
    print("\n--- 7. Testing Credential Leakage Prevention ---")

    # Login demo user to get valid token
    login_res = client.post(
        "/api/auth/login",
        json={"email": "demo@greengrid.com", "password": "Demo@1234"},
    )
    valid_token = login_res.json["token"]
    valid_headers = {"Authorization": f"Bearer {valid_token}"}

    responses_to_inspect = [
        login_res.get_data(as_text=True),
        reg_res.get_data(as_text=True),
        client.get("/api/auth/me", headers=valid_headers).get_data(as_text=True),
        client.get("/api/dashboard", headers=valid_headers).get_data(as_text=True),
        client.get("/api/reports/summary", headers=valid_headers).get_data(as_text=True),
    ]

    has_leak = False
    for text_body in responses_to_inspect:
        if "password_hash" in text_body.lower() or "pbkdf2" in text_body.lower() or "demo@1234" in text_body:
            has_leak = True

    record_test(not has_leak, "Plain passwords and password hashes never appear in any API response")

    # =========================================================================
    # 8. Existing Endpoints Functionality & Data Integrity
    # =========================================================================
    print("\n--- 8. Testing Existing Endpoints Return Unmodified Data Contracts ---")

    # GET /api/auth/me
    me_res = client.get("/api/auth/me", headers=valid_headers)
    record_test(
        me_res.status_code == 200 and me_res.json["user"]["email"] == "demo@greengrid.com",
        "GET /api/auth/me returns authenticated user details",
    )

    # GET /api/dashboard
    dash_res = client.get("/api/dashboard", headers=valid_headers)
    record_test(
        dash_res.status_code == 200
        and dash_res.json["kpis"]["total_locations"] == 12
        and "trends" in dash_res.json,
        "GET /api/dashboard returns complete KPI and trend datasets (12 Pune locations)",
    )

    # GET /api/locations
    loc_res = client.get("/api/locations", headers=valid_headers)
    record_test(
        loc_res.status_code == 200 and len(loc_res.json["locations"]) == 12,
        "GET /api/locations returns all 12 Pune wards with coordinates & risk",
    )

    # POST /api/analyze
    sim_res = client.post(
        "/api/analyze",
        headers=valid_headers,
        json={"location_id": 1, "pollution_index": 210, "green_cover_pct": 14},
    )
    record_test(
        sim_res.status_code == 201
        and sim_res.json["results"]["risk_level"] == "HIGH"
        and "three_params" in sim_res.json["results"],
        "POST /api/analyze calculates risk and returns 3D scene parameters",
    )

    # GET /api/recommendations
    rec_res = client.get("/api/recommendations", headers=valid_headers)
    record_test(
        rec_res.status_code == 200 and len(rec_res.json["recommendations"]) > 0,
        "GET /api/recommendations returns categorized interventions catalog",
    )

    # GET /api/reports/summary
    rep_res = client.get("/api/reports/summary", headers=valid_headers)
    record_test(
        rep_res.status_code == 200
        and "locations_report" in rep_res.json
        and "user_analysis_history" in rep_res.json,
        "GET /api/reports/summary returns comprehensive environmental report and user history",
    )

    # =========================================================================
    # 9. Location-Aware Risk Estimation & Geocoding Proxies
    # =========================================================================
    print("\n--- 9. Testing Location-Aware Risk Estimation & Geocoding Proxies ---")
    from unittest.mock import patch, MagicMock

    # 9.1 /api/risk/estimate without a token returns 401
    unauth_est = client.get("/api/risk/estimate?lat=18.61&lng=73.76")
    record_test(
        unauth_est.status_code == 401,
        "GET /api/risk/estimate without token returns 401",
    )

    # 9.2 Invalid lat or lng returns 400
    inv_lat = client.get("/api/risk/estimate?lat=abc&lng=73.76", headers=valid_headers)
    record_test(
        inv_lat.status_code == 400,
        "GET /api/risk/estimate with non-numeric lat returns 400",
    )
    inv_range = client.get("/api/risk/estimate?lat=95.0&lng=73.76", headers=valid_headers)
    record_test(
        inv_range.status_code == 400,
        "GET /api/risk/estimate with lat > 90 returns 400",
    )
    missing_coords = client.get("/api/risk/estimate?lat=18.5", headers=valid_headers)
    record_test(
        missing_coords.status_code == 400,
        "GET /api/risk/estimate with missing lng returns 400",
    )

    # 9.3 Point exactly at a sample location returns the same risk as /api/locations (method sample_location)
    locs_res = client.get("/api/locations", headers=valid_headers)
    sample_first = locs_res.json["locations"][0]
    sample_exact_res = client.get(
        f"/api/risk/estimate?lat={sample_first['latitude']}&lng={sample_first['longitude']}",
        headers=valid_headers,
    )
    exact_data = sample_exact_res.json
    record_test(
        sample_exact_res.status_code == 200
        and exact_data.get("covered") is True
        and exact_data.get("method") == "sample_location"
        and exact_data.get("risk") == sample_first["risk_level"],
        "A point exactly at a sample location returns method sample_location and matching risk level",
        f"Expected {sample_first['risk_level']}, got {exact_data.get('risk')}",
    )

    # 9.4 Tathawade, Pune (around lat 18.61, lng 73.76) returns covered true, idw_estimate, 3 nearest, risk, confidence
    tathawade_res = client.get(
        "/api/risk/estimate?lat=18.61&lng=73.76",
        headers=valid_headers,
    )
    t_data = tathawade_res.json
    record_test(
        tathawade_res.status_code == 200
        and t_data.get("covered") is True
        and t_data.get("method") == "idw_estimate"
        and len(t_data.get("nearest", [])) == 3
        and t_data.get("risk") in ["HIGH", "MEDIUM", "LOW"]
        and t_data.get("confidence") in ["high", "medium", "low"]
        and "disclaimer" in t_data,
        "Tathawade point returns covered: true, idw_estimate, 3 nearest locations, risk, and confidence label",
        f"Data: {t_data}",
    )

    # 9.5 Far away point (Delhi: lat 28.61, lng 77.20) returns covered: false
    delhi_res = client.get(
        "/api/risk/estimate?lat=28.61&lng=77.20",
        headers=valid_headers,
    )
    d_data = delhi_res.json
    record_test(
        delhi_res.status_code == 200
        and d_data.get("covered") is False
        and "Pune area only" in d_data.get("message", "")
        and "risk" not in d_data,
        "Point far away (Delhi) returns covered: false with Pune demo notice and no risk",
    )

    # 9.6 /api/geocode query length validation (< 3 rejected with 400)
    short_geo = client.get("/api/geocode?q=ab", headers=valid_headers)
    record_test(
        short_geo.status_code == 400,
        "GET /api/geocode with query < 3 chars returns 400",
    )

    # 9.7 /api/geocode when Nominatim is unreachable returns 503 without crashing
    import app as app_module
    app_module.NOMINATIM_CACHE.clear()
    with patch("urllib.request.urlopen", side_effect=Exception("Nominatim network timeout")):
        unreachable_geo = client.get("/api/geocode?q=UnreachableLocation", headers=valid_headers)
        record_test(
            unreachable_geo.status_code == 503
            and "unavailable" in unreachable_geo.json.get("message", "").lower(),
            "GET /api/geocode handles unreachable Nominatim cleanly with 503 without crashing",
        )

    # 9.8 /api/geocode caching & 1 req/sec rate limit (mocked)
    mock_search_json = json.dumps([
        {
            "place_id": 99901,
            "display_name": "Tathawade, Pimpri-Chinchwad, Pune, Maharashtra, India",
            "name": "Tathawade",
            "lat": "18.6161",
            "lon": "73.7601",
        }
    ]).encode("utf-8")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = mock_search_json
    mock_resp.__enter__.return_value = mock_resp

    app_module.NOMINATIM_CACHE.clear()
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        # First call hits mock
        geo_1 = client.get("/api/geocode?q=Tathawade", headers=valid_headers)
        call_count_1 = mock_urlopen.call_count

        # Second call within 10 min hits cache, so urlopen is not called again
        geo_2 = client.get("/api/geocode?q=Tathawade", headers=valid_headers)
        call_count_2 = mock_urlopen.call_count

    record_test(
        geo_1.status_code == 200
        and geo_2.status_code == 200
        and call_count_1 == 1
        and call_count_2 == 1
        and len(geo_1.json.get("results", [])) == 1
        and geo_1.json["results"][0]["name"] == "Tathawade",
        "GET /api/geocode caches results in memory so second request doesn't hit Nominatim",
    )

    # Rate limiting test: verify wait_for_nominatim_rate_limit sleeps if invoked too fast
    with patch("time.sleep") as mock_sleep:
        app_module.LAST_NOMINATIM_REQUEST_TIME = time.time()  # just requested
        app_module.wait_for_nominatim_rate_limit()
        record_test(
            mock_sleep.called,
            "wait_for_nominatim_rate_limit enforces 1 request per second spacing by sleeping",
        )

    # 9.9 /api/geocode/reverse tests
    rev_invalid = client.get("/api/geocode/reverse?lat=invalid&lng=73.76", headers=valid_headers)
    record_test(
        rev_invalid.status_code == 400,
        "GET /api/geocode/reverse with invalid coords returns 400",
    )

    mock_rev_json = json.dumps({
        "place_id": 88812,
        "display_name": "Tathawade, Haveli, Pune, Maharashtra, 411033, India",
        "address": {
            "suburb": "Tathawade",
            "city": "Pune",
            "state": "Maharashtra",
        }
    }).encode("utf-8")

    mock_rev_resp = MagicMock()
    mock_rev_resp.status = 200
    mock_rev_resp.read.return_value = mock_rev_json
    mock_rev_resp.__enter__.return_value = mock_rev_resp

    with patch("urllib.request.urlopen", return_value=mock_rev_resp):
        rev_res = client.get("/api/geocode/reverse?lat=18.61&lng=73.76", headers=valid_headers)

    record_test(
        rev_res.status_code == 200
        and rev_res.json.get("name") == "Tathawade",
        "GET /api/geocode/reverse returns extracted suburb name from Nominatim",
    )

    # =========================================================================
    # Summary
    # =========================================================================
    print("=" * 65)
    print(f"FINAL RESULT: {passed} / {total} tests passed ({round((passed/total)*100)}% SUCCESS)")
    print("=" * 65)

    # Cleanup temporary database
    try:
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
            print("[Cleanup] Temporary SQLite test database removed cleanly.")
    except Exception as e:
        print(f"[Cleanup Note] Could not remove temp file: {e}")

    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
