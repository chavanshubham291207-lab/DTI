"""
GREEN GRID - Flask Application Server
Provides RESTful APIs for Urban Planning, Environmental Risk Analysis,
Auth/JWT verification, GIS Location Feeds, and Reports.
"""

import os
import sqlite3
import math
import time
import threading
import json
import urllib.request
import urllib.parse
import urllib.error
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from dotenv import load_dotenv

from database import get_db, init_db
from auth import (
    create_jwt_token,
    login_required,
    password_problems,
    validate_email_format,
    check_rate_limit,
    record_failed_attempt,
    clear_failed_attempts,
)
from werkzeug.security import generate_password_hash, check_password_hash
from analysis import calculate_risk, CONFIG as ANALYSIS_CONFIG

load_dotenv()

app = Flask(__name__)
# Enable CORS for frontend origins (supporting both localhost and 127.0.0.1 on ports 5173, 5174, 5175, 3000)
raw_cors = os.getenv("CORS_ORIGIN", "http://localhost:5173,http://127.0.0.1:5173")
configured_origins = [o.strip() for o in raw_cors.split(",") if o.strip()]
default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:5175",
    "http://127.0.0.1:5175",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
allowed_origins = list(dict.fromkeys(default_origins + configured_origins))
CORS(app, origins=allowed_origins, supports_credentials=True)

# -------------------------------------------------------------
# PUBLIC ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint to verify backend status."""
    return jsonify({
        "status": "healthy",
        "service": "GREEN GRID API",
        "version": "1.0.0",
        "environment": "academic_prototype",
        "city_focus": "Pune, Maharashtra, India",
    }), 200


@app.route("/api/auth/register", methods=["POST"])
def register():
    """
    Registers a new user.
    Validates name (2-60 chars), email format, and the strict password policy.
    Rejects duplicate emails (case-insensitive) with 409 Conflict.
    Returns 201 with JWT token and user info (never plain passwords or hashes).
    """
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # Validate name (2 to 60 characters)
    if not name or len(name) < 2 or len(name) > 60:
        return jsonify({
            "status": "error",
            "message": "Full Name must be between 2 and 60 characters."
        }), 400

    # Validate email format
    if not email or not validate_email_format(email):
        return jsonify({
            "status": "error",
            "message": "A valid email address is required."
        }), 400

    # Validate password policy
    problems = password_problems(password)
    if problems:
        return jsonify({
            "status": "error",
            "error": "Password must have: " + ", ".join(problems),
            "problems": problems
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Check duplicate (case-insensitive)
        cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?;", (email,))
        if cursor.fetchone():
            conn.close()
            return jsonify({
                "status": "error",
                "message": "This email address is already registered. Please log in."
            }), 409

        password_hash = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO users (name, email, password_hash, role)
            VALUES (?, ?, ?, 'user');
        """, (name, email, password_hash))
        conn.commit()

        user_id = cursor.lastrowid
        conn.close()

        token = create_jwt_token(user_id, email, name, "user")

        return jsonify({
            "status": "success",
            "message": "User registration successful.",
            "token": token,
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
                "role": "user"
            }
        }), 201

    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": f"Server error during registration: {str(e)}"}), 500


@app.route("/api/auth/login", methods=["POST"])
def login():
    """
    Authenticates user credentials and issues a JWT token.
    Applies in-memory rate limiting (after 5 failed attempts per email in 5 mins returns 429).
    Returns identical generic error message for incorrect email or password (401).
    """
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required."}), 400

    # Rate Limit Check: 6th attempt after 5 failures triggers 429
    if not check_rate_limit(email):
        return jsonify({
            "status": "error",
            "message": "Too many failed login attempts. For security, please wait 5 minutes before trying again."
        }), 429

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, password_hash, role FROM users WHERE LOWER(email) = ?;", (email,))
    user = cursor.fetchone()
    conn.close()

    # Generic invalid credentials message for both wrong email and wrong password
    invalid_cred_message = "Invalid email or password."

    if not user:
        record_failed_attempt(email)
        return jsonify({"status": "error", "message": invalid_cred_message}), 401

    if not check_password_hash(user["password_hash"], password):
        record_failed_attempt(email)
        return jsonify({"status": "error", "message": invalid_cred_message}), 401

    # Login successful: clear failure history
    clear_failed_attempts(email)
    token = create_jwt_token(user["id"], user["email"], user["name"], user["role"])

    return jsonify({
        "status": "success",
        "message": "Login successful.",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"]
        }
    }), 200


# -------------------------------------------------------------
# PROTECTED ENDPOINTS (@login_required)
# -------------------------------------------------------------

@app.route("/api/auth/me", methods=["GET"])
@login_required
def get_current_user():
    """Returns profile of currently authenticated user from token."""
    user_id = g.current_user["user_id"]
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, role, created_at FROM users WHERE id = ?;", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"status": "error", "message": "User account not found."}), 404

    return jsonify({
        "status": "success",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "created_at": user["created_at"],
        }
    }), 200


@app.route("/api/dashboard", methods=["GET"])
@login_required
def get_dashboard():
    """
    Returns aggregated metrics, monthly pollution trends, green cover distribution,
    risk categorization, and recent environmental observations for Pune.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Total locations
    cursor.execute("SELECT COUNT(*) AS total_locations FROM locations;")
    total_locations = cursor.fetchone()["total_locations"]

    # Latest observation per location using a subquery
    cursor.execute("""
        SELECT l.id, l.name, l.ward_code, l.latitude, l.longitude,
               o.aqi, o.pm25, o.green_cover_pct, o.surface_temp_c, o.recorded_date
        FROM locations l
        INNER JOIN observations o ON o.location_id = l.id
        WHERE o.recorded_date = (
            SELECT MAX(o2.recorded_date) FROM observations o2 WHERE o2.location_id = l.id
        )
        ORDER BY l.name ASC;
    """)
    latest_observations = cursor.fetchall()

    total_aqi = 0
    total_green = 0
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    locations_summary = []

    for row in latest_observations:
        aqi = row["aqi"]
        green = row["green_cover_pct"]
        total_aqi += aqi
        total_green += green

        # Evaluate risk category
        risk_data = calculate_risk(aqi, green)
        level = risk_data["risk_level"]
        if level == "HIGH":
            high_risk_count += 1
        elif level == "MEDIUM":
            medium_risk_count += 1
        else:
            low_risk_count += 1

        locations_summary.append({
            "id": row["id"],
            "name": row["name"],
            "ward_code": row["ward_code"],
            "latitude": row["latitude"],
            "longitude": row["longitude"],
            "aqi": aqi,
            "pm25": row["pm25"],
            "green_cover_pct": green,
            "surface_temp_c": row["surface_temp_c"],
            "risk_level": level,
            "score": risk_data["score"],
        })

    count = len(latest_observations) or 1
    avg_aqi = round(total_aqi / count, 1)
    avg_green = round(total_green / count, 1)

    # Monthly trends (aggregating across all locations by recorded_date)
    cursor.execute("""
        SELECT recorded_date,
               ROUND(AVG(aqi), 1) as avg_aqi,
               ROUND(AVG(pm25), 1) as avg_pm25,
               ROUND(AVG(green_cover_pct), 1) as avg_green,
               ROUND(AVG(surface_temp_c), 1) as avg_temp
        FROM observations
        GROUP BY recorded_date
        ORDER BY recorded_date ASC;
    """)
    trends = [dict(r) for r in cursor.fetchall()]

    # Recent observations (top 8 latest entries)
    cursor.execute("""
        SELECT o.id, l.name as location_name, l.ward_code, o.recorded_date, o.aqi, o.pm25, o.green_cover_pct, o.surface_temp_c
        FROM observations o
        JOIN locations l ON o.location_id = l.id
        ORDER BY o.recorded_date DESC, o.id DESC
        LIMIT 8;
    """)
    recent_obs = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return jsonify({
        "status": "success",
        "data_notice": "DEMO DATA — Pune Urban Planning Academic Model",
        "kpis": {
            "total_locations": total_locations,
            "avg_pollution_aqi": avg_aqi,
            "avg_green_cover_pct": avg_green,
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "low_risk_count": low_risk_count,
        },
        "trends": trends,
        "recent_observations": recent_obs,
        "locations": locations_summary,
    }), 200


@app.route("/api/locations", methods=["GET"])
@login_required
def get_locations():
    """
    Returns list of all Pune locations with geographic coordinates,
    latest observation data, and evaluated risk levels for GIS mapping.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT l.id, l.name, l.ward_code, l.area_km2, l.latitude, l.longitude, l.description,
               o.aqi, o.pm25, o.green_cover_pct, o.surface_temp_c, o.recorded_date
        FROM locations l
        LEFT JOIN observations o ON o.location_id = l.id AND o.recorded_date = (
            SELECT MAX(o2.recorded_date) FROM observations o2 WHERE o2.location_id = l.id
        )
        ORDER BY l.name ASC;
    """)
    rows = cursor.fetchall()
    conn.close()

    locations = []
    for row in rows:
        aqi = row["aqi"] or 100
        green = row["green_cover_pct"] or 25.0
        risk_info = calculate_risk(aqi, green)

        locations.append({
            "id": row["id"],
            "name": row["name"],
            "ward_code": row["ward_code"],
            "area_km2": row["area_km2"],
            "latitude": row["latitude"],
            "longitude": row["longitude"],
            "description": row["description"],
            "latest_observation": {
                "recorded_date": row["recorded_date"],
                "aqi": aqi,
                "pm25": row["pm25"],
                "green_cover_pct": green,
                "surface_temp_c": row["surface_temp_c"],
            },
            "risk_level": risk_info["risk_level"],
            "risk_color": risk_info["risk_color"],
            "score": risk_info["score"],
            "explanation": risk_info["explanation"],
        })

    return jsonify({
        "status": "success",
        "data_notice": "DEMO DATA",
        "locations": locations,
    }), 200


@app.route("/api/observations", methods=["GET"])
@login_required
def get_observations():
    """
    Returns historical observations filtered optionally by location_id.
    """
    location_id = request.args.get("location_id")
    limit = min(int(request.args.get("limit", 100)), 300)

    conn = get_db()
    cursor = conn.cursor()

    if location_id:
        cursor.execute("""
            SELECT o.id, o.location_id, l.name as location_name, l.ward_code,
                   o.recorded_date, o.aqi, o.pm25, o.green_cover_pct, o.surface_temp_c
            FROM observations o
            JOIN locations l ON o.location_id = l.id
            WHERE o.location_id = ?
            ORDER BY o.recorded_date DESC
            LIMIT ?;
        """, (location_id, limit))
    else:
        cursor.execute("""
            SELECT o.id, o.location_id, l.name as location_name, l.ward_code,
                   o.recorded_date, o.aqi, o.pm25, o.green_cover_pct, o.surface_temp_c
            FROM observations o
            JOIN locations l ON o.location_id = l.id
            ORDER BY o.recorded_date DESC
            LIMIT ?;
        """, (limit,))

    rows = cursor.fetchall()
    conn.close()

    return jsonify({
        "status": "success",
        "data_notice": "DEMO DATA",
        "count": len(rows),
        "observations": [dict(r) for r in rows],
    }), 200


@app.route("/api/analyze", methods=["POST"])
@login_required
def analyze_environmental_data():
    """
    Processes environmental analysis inputs.
    Validates location_id, pollution_index (0-500), and green_cover_pct (0-100).
    Saves to analysis_results with user_id to preserve the user's history.
    Returns calculated risk, explanation, recommendations, and 3D preview scene parameters.
    """
    data = request.get_json() or {}
    location_id = data.get("location_id")
    pollution_index = data.get("pollution_index")
    green_cover_pct = data.get("green_cover_pct")

    # Backend Validation
    if location_id is None:
        return jsonify({"status": "error", "message": "Location selection is required."}), 400

    try:
        pollution_index = float(pollution_index)
        green_cover_pct = float(green_cover_pct)
    except (ValueError, TypeError):
        return jsonify({
            "status": "error",
            "message": "Pollution indicator and Green Cover % must be numeric numbers."
        }), 400

    if not (0 <= pollution_index <= 500):
        return jsonify({
            "status": "error",
            "message": "Pollution indicator (AQI) must be between 0 and 500."
        }), 400

    if not (0 <= green_cover_pct <= 100):
        return jsonify({
            "status": "error",
            "message": "Green Cover percentage must be between 0% and 100%."
        }), 400

    conn = get_db()
    cursor = conn.cursor()

    # Check location existence
    cursor.execute("SELECT id, name, ward_code FROM locations WHERE id = ?;", (location_id,))
    loc = cursor.fetchone()
    if not loc:
        conn.close()
        return jsonify({"status": "error", "message": f"Location with ID {location_id} not found."}), 404

    # Run deterministic rule engine
    risk_data = calculate_risk(pollution_index, green_cover_pct)

    # Persist to analysis_results with authenticated user_id
    user_id = g.current_user["user_id"]
    cursor.execute("""
        INSERT INTO analysis_results (user_id, location_id, pollution_index, green_cover_pct, risk_level, score, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (
        user_id,
        location_id,
        pollution_index,
        green_cover_pct,
        risk_data["risk_level"],
        risk_data["score"],
        risk_data["explanation"],
    ))
    analysis_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "status": "success",
        "data_notice": "DEMO DATA — Rule-based academic simulation",
        "analysis_id": analysis_id,
        "location": {
            "id": loc["id"],
            "name": loc["name"],
            "ward_code": loc["ward_code"],
        },
        "inputs": {
            "pollution_index": pollution_index,
            "green_cover_pct": green_cover_pct,
        },
        "results": {
            "score": risk_data["score"],
            "risk_level": risk_data["risk_level"],
            "risk_color": risk_data["risk_color"],
            "explanation": risk_data["explanation"],
            "sub_scores": risk_data["sub_scores"],
            "recommendations": risk_data["recommendations"],
            "three_params": risk_data["three_params"],
        }
    }), 201


@app.route("/api/recommendations", methods=["GET"])
@login_required
def get_recommendations():
    """
    Returns rule-based planning recommendations filtered optionally by priority, category, or location_id.
    """
    priority = request.args.get("priority")
    category = request.args.get("category")
    location_id = request.args.get("location_id")

    query = """
        SELECT r.id, r.location_id, l.name as location_name, l.ward_code,
               r.category, r.title, r.description, r.priority, r.estimated_cost,
               r.time_horizon, r.target_metric, r.created_at
        FROM recommendations r
        LEFT JOIN locations l ON r.location_id = l.id
        WHERE 1=1
    """
    params = []

    if priority and priority.upper() != "ALL":
        query += " AND r.priority = ?"
        params.append(priority.upper())

    if category and category.lower() != "all":
        query += " AND LOWER(r.category) LIKE ?"
        params.append(f"%{category.lower()}%")

    if location_id:
        query += " AND r.location_id = ?"
        params.append(location_id)

    query += " ORDER BY CASE r.priority WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, r.id ASC;"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(query, tuple(params))
    recs = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return jsonify({
        "status": "success",
        "data_notice": "DEMO DATA",
        "count": len(recs),
        "recommendations": recs,
    }), 200


@app.route("/api/reports/summary", methods=["GET"])
@login_required
def get_reports_summary():
    """
    Aggregates comprehensive environmental status report,
    including location-wise vulnerability ranking, green cover status,
    action items, and the user's personal analysis run history.
    """
    user_id = g.current_user["user_id"]
    conn = get_db()
    cursor = conn.cursor()

    # User's personal past analyses
    cursor.execute("""
        SELECT a.id, a.pollution_index, a.green_cover_pct, a.risk_level, a.score,
               a.explanation, a.created_at, l.name as location_name, l.ward_code
        FROM analysis_results a
        JOIN locations l ON a.location_id = l.id
        WHERE a.user_id = ?
        ORDER BY a.created_at DESC;
    """, (user_id,))
    user_analyses = [dict(r) for r in cursor.fetchall()]

    # Location rankings
    cursor.execute("""
        SELECT l.id, l.name, l.ward_code, l.area_km2,
               o.aqi, o.pm25, o.green_cover_pct, o.surface_temp_c
        FROM locations l
        LEFT JOIN observations o ON o.location_id = l.id AND o.recorded_date = (
            SELECT MAX(o2.recorded_date) FROM observations o2 WHERE o2.location_id = l.id
        )
        ORDER BY o.aqi DESC;
    """)
    locations_data = []
    for row in cursor.fetchall():
        aqi = row["aqi"] or 100
        green = row["green_cover_pct"] or 25.0
        risk = calculate_risk(aqi, green)
        locations_data.append({
            "id": row["id"],
            "name": row["name"],
            "ward_code": row["ward_code"],
            "area_km2": row["area_km2"],
            "aqi": aqi,
            "pm25": row["pm25"],
            "green_cover_pct": green,
            "surface_temp_c": row["surface_temp_c"],
            "risk_level": risk["risk_level"],
            "score": risk["score"],
        })

    # Recommendations catalog
    cursor.execute("""
        SELECT r.id, r.category, r.title, r.priority, r.estimated_cost, r.time_horizon, l.name as location_name
        FROM recommendations r
        LEFT JOIN locations l ON r.location_id = l.id
        ORDER BY CASE r.priority WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END;
    """)
    recs_list = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return jsonify({
        "status": "success",
        "data_notice": "DEMO DATA — DTI Project Academic Prototype",
        "generated_by": g.current_user["name"],
        "user_email": g.current_user["email"],
        "locations_report": locations_data,
        "recommendations_summary": recs_list,
        "user_analysis_history": user_analyses,
        "thresholds_applied": {
            "pollution_high": ANALYSIS_CONFIG["POLLUTION_HIGH_THRESHOLD"],
            "pollution_moderate": ANALYSIS_CONFIG["POLLUTION_MODERATE_THRESHOLD"],
            "green_cover_low": ANALYSIS_CONFIG["GREEN_COVER_LOW_THRESHOLD"],
        }
    }), 200


# -------------------------------------------------------------
# LOCATION-AWARE GIS RISK ESTIMATION & GEOLOCATION PROXIES
# -------------------------------------------------------------

NOMINATIM_LOCK = threading.Lock()
LAST_NOMINATIM_REQUEST_TIME = 0.0
NOMINATIM_CACHE = {}  # key -> (timestamp, data_dict)
NOMINATIM_CACHE_TTL_SEC = 600.0  # 10 minutes cache


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Computes great-circle distance between two geographic coordinates in kilometers.
    """
    earth_radius_km = 6371.0
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2.0) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d_lon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return earth_radius_km * c


def wait_for_nominatim_rate_limit():
    """Enforces at most 1 outgoing request per second to OpenStreetMap Nominatim."""
    global LAST_NOMINATIM_REQUEST_TIME
    with NOMINATIM_LOCK:
        now = time.time()
        elapsed = now - LAST_NOMINATIM_REQUEST_TIME
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
        LAST_NOMINATIM_REQUEST_TIME = time.time()


def get_nominatim_user_agent() -> str:
    contact_email = os.getenv("NOMINATIM_CONTACT_EMAIL", "student.greengrid@example.com").strip()
    return f"GreenGrid-UrbanApp/1.0 ({contact_email})"


@app.route("/api/risk/estimate", methods=["GET"])
@login_required
def estimate_risk():
    """
    Location-aware risk estimation endpoint for any point.
    Uses inverse-distance weighting (IDW) from 3 nearest sample points (or direct sample if within 0.5 km).
    Rejects coordinates farther than 25 km from Pune sample points with covered: false.
    """
    lat_raw = request.args.get("lat")
    lng_raw = request.args.get("lng")

    if lat_raw is None or lng_raw is None or lat_raw == "" or lng_raw == "":
        return jsonify({
            "status": "error",
            "message": "Latitude ('lat') and longitude ('lng') query parameters are required."
        }), 400

    try:
        lat = float(lat_raw)
        lng = float(lng_raw)
    except (ValueError, TypeError):
        return jsonify({
            "status": "error",
            "message": "Latitude and longitude must be valid floating point numbers."
        }), 400

    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lng <= 180.0):
        return jsonify({
            "status": "error",
            "message": "Latitude must be between -90 and 90, and longitude between -180 and 180."
        }), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT l.id, l.name, l.ward_code, l.latitude, l.longitude,
               o.aqi, o.pm25, o.green_cover_pct, o.surface_temp_c, o.recorded_date
        FROM locations l
        LEFT JOIN observations o ON o.location_id = l.id AND o.recorded_date = (
            SELECT MAX(o2.recorded_date) FROM observations o2 WHERE o2.location_id = l.id
        )
        ORDER BY l.name ASC;
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return jsonify({
            "status": "error",
            "message": "No sample locations found in system database."
        }), 500

    points = []
    for r in rows:
        dist = haversine_km(lat, lng, float(r["latitude"]), float(r["longitude"]))
        points.append({
            "id": r["id"],
            "name": r["name"],
            "ward_code": r["ward_code"],
            "latitude": float(r["latitude"]),
            "longitude": float(r["longitude"]),
            "aqi": float(r["aqi"]) if r["aqi"] is not None else 100.0,
            "green_cover_pct": float(r["green_cover_pct"]) if r["green_cover_pct"] is not None else 25.0,
            "distance_km": dist,
        })

    points.sort(key=lambda p: p["distance_km"])
    nearest_loc = points[0]
    min_dist = nearest_loc["distance_km"]

    # Outside coverage threshold (> 25 km from nearest Pune sample point)
    if min_dist > 25.0:
        return jsonify({
            "status": "success",
            "covered": False,
            "message": "Demo data covers the Pune area only."
        }), 200

    # Confidence label determination
    if min_dist <= 2.0:
        confidence = "high"
    elif min_dist <= 5.0:
        confidence = "medium"
    else:
        confidence = "low"

    # Direct match within 0.5 km of a sample point
    if min_dist <= 0.5:
        pollution_index = round(nearest_loc["aqi"], 1)
        green_cover = round(nearest_loc["green_cover_pct"], 1)
        method = "sample_location"
        nearest_list = [
            {
                "name": nearest_loc["name"],
                "distance_km": round(nearest_loc["distance_km"], 1),
                "weight_percent": 100.0,
            }
        ]
    else:
        top3 = points[:3]
        weights = [1.0 / (p["distance_km"] ** 2) for p in top3]
        sum_weights = sum(weights)
        pollution_index = round(sum(w * p["aqi"] for w, p in zip(weights, top3)) / sum_weights, 1)
        green_cover = round(sum(w * p["green_cover_pct"] for w, p in zip(weights, top3)) / sum_weights, 1)
        method = "idw_estimate"
        nearest_list = [
            {
                "name": p["name"],
                "distance_km": round(p["distance_km"], 1),
                "weight_percent": round((w / sum_weights) * 100.0, 1),
            }
            for p, w in zip(top3, weights)
        ]

    # Evaluate risk using existing deterministic analyze rule engine
    risk_data = calculate_risk(pollution_index, green_cover)

    return jsonify({
        "status": "success",
        "covered": True,
        "method": method,
        "pollution_index": pollution_index,
        "green_cover": green_cover,
        "risk": risk_data["risk_level"],
        "risk_level": risk_data["risk_level"],
        "risk_color": risk_data["risk_color"],
        "score": risk_data["score"],
        "explanation": risk_data["explanation"],
        "recommendations": risk_data["recommendations"],
        "confidence": confidence,
        "nearest": nearest_list,
        "disclaimer": "Estimated from demo data, not a measurement"
    }), 200


@app.route("/api/geocode", methods=["GET"])
@login_required
def geocode_search():
    """
    Proxies search query to OpenStreetMap Nominatim with viewbox bias to Pune.
    Enforces 3-100 character query length, 1 req/sec rate limit, in-memory caching,
    proper User-Agent contact email, and 5 second timeout.
    """
    q = request.args.get("q", "").strip()
    if len(q) < 3 or len(q) > 100:
        return jsonify({
            "status": "error",
            "message": "Search query must be between 3 and 100 characters."
        }), 400

    cache_key = f"search:{q.lower()}"
    now = time.time()
    if cache_key in NOMINATIM_CACHE:
        cached_ts, cached_payload = NOMINATIM_CACHE[cache_key]
        if now - cached_ts < NOMINATIM_CACHE_TTL_SEC:
            return jsonify(cached_payload), 200

    wait_for_nominatim_rate_limit()

    params = {
        "q": q,
        "format": "jsonv2",
        "viewbox": "73.5,18.8,74.2,18.3",
        "countrycodes": "in",
        "limit": "5",
    }
    url = f"https://nominatim.openstreetmap.org/search?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": get_nominatim_user_agent(),
            "Accept": "application/json",
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            if resp.status != 200:
                return jsonify({
                    "status": "error",
                    "message": "Geocoding service is temporarily unavailable. Please try again."
                }), 503
            body = resp.read().decode("utf-8")
            raw_results = json.loads(body)
    except Exception:
        return jsonify({
            "status": "error",
            "message": "Geocoding service is temporarily unavailable. Please try again."
        }), 503

    results = []
    for item in raw_results:
        try:
            results.append({
                "place_id": item.get("place_id"),
                "display_name": item.get("display_name"),
                "name": item.get("name") or item.get("display_name", "").split(",")[0].strip(),
                "lat": float(item["lat"]),
                "lng": float(item["lon"]),
            })
        except (KeyError, ValueError):
            continue

    payload = {
        "status": "success",
        "results": results
    }
    NOMINATIM_CACHE[cache_key] = (time.time(), payload)
    return jsonify(payload), 200


@app.route("/api/geocode/reverse", methods=["GET"])
@login_required
def geocode_reverse():
    """
    Reverse geocodes coordinates to a human-readable suburb or place name via Nominatim.
    Enforces coordinate bounds, rate limit, 10 min cache, and 5 second timeout.
    """
    lat_raw = request.args.get("lat")
    lng_raw = request.args.get("lng")

    if lat_raw is None or lng_raw is None or lat_raw == "" or lng_raw == "":
        return jsonify({
            "status": "error",
            "message": "Latitude ('lat') and longitude ('lng') query parameters are required."
        }), 400

    try:
        lat = float(lat_raw)
        lng = float(lng_raw)
    except (ValueError, TypeError):
        return jsonify({
            "status": "error",
            "message": "Latitude and longitude must be valid floating point numbers."
        }), 400

    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lng <= 180.0):
        return jsonify({
            "status": "error",
            "message": "Latitude must be between -90 and 90, and longitude between -180 and 180."
        }), 400

    cache_key = f"reverse:{round(lat, 5)}:{round(lng, 5)}"
    now = time.time()
    if cache_key in NOMINATIM_CACHE:
        cached_ts, cached_payload = NOMINATIM_CACHE[cache_key]
        if now - cached_ts < NOMINATIM_CACHE_TTL_SEC:
            return jsonify(cached_payload), 200

    wait_for_nominatim_rate_limit()

    params = {
        "lat": str(lat),
        "lon": str(lng),
        "format": "jsonv2",
        "zoom": "14",
    }
    url = f"https://nominatim.openstreetmap.org/reverse?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": get_nominatim_user_agent(),
            "Accept": "application/json",
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            if resp.status != 200:
                return jsonify({
                    "status": "error",
                    "message": "Reverse geocoding service is temporarily unavailable."
                }), 503
            body = resp.read().decode("utf-8")
            raw_data = json.loads(body)
    except Exception:
        return jsonify({
            "status": "error",
            "message": "Reverse geocoding service is temporarily unavailable."
        }), 503

    addr = raw_data.get("address", {})
    short_name = (
        addr.get("suburb")
        or addr.get("neighbourhood")
        or addr.get("residential")
        or addr.get("road")
        or addr.get("city_district")
        or raw_data.get("name")
        or raw_data.get("display_name", "").split(",")[0].strip()
        or f"{lat:.4f}, {lng:.4f}"
    )

    payload = {
        "status": "success",
        "display_name": raw_data.get("display_name", f"{lat:.4f}, {lng:.4f}"),
        "name": short_name,
        "lat": lat,
        "lng": lng,
    }
    NOMINATIM_CACHE[cache_key] = (time.time(), payload)
    return jsonify(payload), 200


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("PORT", 5000))
    print(f"[GREEN GRID] Flask server starting on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
