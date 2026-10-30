"""
GREEN GRID - Database Seed Script
Populates the SQLite database with 12 Pune urban locations, 6 months of demo observations,
rule-based recommendations, pre-calculated demo analyses, and demo user accounts.
Idempotent design: Safe to re-run multiple times without duplicate key errors.
"""

from datetime import datetime
from werkzeug.security import generate_password_hash
from database import get_db, init_db

# Pune Urban Planning Ward Data
PUNE_LOCATIONS = [
    {
        "name": "Shivajinagar",
        "ward_code": "PN-01",
        "area_km2": 8.4,
        "latitude": 18.5314,
        "longitude": 73.8446,
        "description": "Central municipal transit and institutional hub with high daytime bus traffic and congested intersections.",
    },
    {
        "name": "Hinjewadi",
        "ward_code": "PN-02",
        "area_km2": 21.5,
        "latitude": 18.5913,
        "longitude": 73.7389,
        "description": "Major IT & technology park zone experiencing high vehicular commuter traffic and ongoing urban construction.",
    },
    {
        "name": "Kothrud",
        "ward_code": "PN-03",
        "area_km2": 12.2,
        "latitude": 18.5074,
        "longitude": 73.8077,
        "description": "Established residential sector nestled near ARAI hills with healthy legacy tree canopy cover.",
    },
    {
        "name": "Hadapsar",
        "ward_code": "PN-04",
        "area_km2": 19.8,
        "latitude": 18.5089,
        "longitude": 73.9259,
        "description": "Hybrid industrial fabrication cluster and tech enclave prone to fugitive dust and industrial exhaust.",
    },
    {
        "name": "Swargate",
        "ward_code": "PN-05",
        "area_km2": 6.7,
        "latitude": 18.5018,
        "longitude": 73.8586,
        "description": "Dense inter-city bus terminal nexus with severe peak-hour idling emissions and low green buffer.",
    },
    {
        "name": "Pimpri",
        "ward_code": "PN-06",
        "area_km2": 24.1,
        "latitude": 18.6298,
        "longitude": 73.7997,
        "description": "Heavy automotive and engineering industrial zone with elevated particulate and sulfur emissions.",
    },
    {
        "name": "Baner",
        "ward_code": "PN-07",
        "area_km2": 14.3,
        "latitude": 18.5590,
        "longitude": 73.7868,
        "description": "Rapidly urbanized western residential corridor bordered by biodiversity hills.",
    },
    {
        "name": "Katraj",
        "ward_code": "PN-08",
        "area_km2": 16.5,
        "latitude": 18.4575,
        "longitude": 73.8677,
        "description": "Southern gateway featuring Katraj lake basin, animal park sanctuary, and heavy bypass truck transit.",
    },
    {
        "name": "Viman Nagar",
        "ward_code": "PN-09",
        "area_km2": 9.1,
        "latitude": 18.5679,
        "longitude": 73.9143,
        "description": "Airport proximity commercial district with shopping hubs, high density, and moderate tree avenues.",
    },
    {
        "name": "Wakad",
        "ward_code": "PN-10",
        "area_km2": 11.8,
        "latitude": 18.5987,
        "longitude": 73.7634,
        "description": "High-rise residential sector with significant impervious concrete surface coverage.",
    },
    {
        "name": "Aundh",
        "ward_code": "PN-11",
        "area_km2": 7.9,
        "latitude": 18.5580,
        "longitude": 73.8070,
        "description": "Planned eco-conscious neighborhood with wide shaded boulevards, river proximity, and low pollution.",
    },
    {
        "name": "Koregaon Park",
        "ward_code": "PN-12",
        "area_km2": 5.8,
        "latitude": 18.5362,
        "longitude": 73.8958,
        "description": "Mula-Mutha riverfront zone boasting dense heritage banyan trees, high canopy, and recreational zones.",
    },
]

# 6 Months of Monthly Demo Environmental Observations (May 2026 - Oct 2026)
MONTHS_DATA = [
    ("2026-05-15", 1.08, 1.05, 0.95, 3.2),  # May: Pre-monsoon dry heat & dust
    ("2026-06-15", 0.92, 0.90, 1.05, 0.5),  # June: Monsoon arrival, air washed
    ("2026-07-15", 0.70, 0.65, 1.15, -2.1), # July: Peak monsoon, lush green
    ("2026-08-15", 0.72, 0.68, 1.18, -1.8), # August: High green, clean air
    ("2026-09-15", 0.90, 0.88, 1.10, 0.2),  # September: Monsoon retreating
    ("2026-10-15", 1.15, 1.18, 1.02, 1.5),  # October: Post-monsoon, inversion starts
]

# Base location profiles: (Base AQI, Base PM2.5, Base Green Cover %, Base Surface Temp C)
LOCATION_BASELINES = {
    "Shivajinagar": (175, 78.0, 22.0, 34.0),
    "Hinjewadi": (155, 68.0, 26.0, 33.5),
    "Kothrud": (88, 38.0, 42.0, 31.0),
    "Hadapsar": (195, 92.0, 18.0, 35.5),
    "Swargate": (210, 105.0, 14.0, 36.2),
    "Pimpri": (185, 89.0, 20.0, 35.0),
    "Baner": (115, 52.0, 34.0, 32.0),
    "Katraj": (130, 60.0, 38.0, 31.5),
    "Viman Nagar": (140, 64.0, 24.0, 33.8),
    "Wakad": (150, 70.0, 21.0, 34.5),
    "Aundh": (82, 35.0, 44.0, 30.5),
    "Koregaon Park": (78, 32.0, 48.0, 29.8),
}


def seed_database():
    """Execute complete database seeding in an idempotent fashion."""
    init_db()
    conn = get_db()
    cursor = conn.cursor()

    print("[Seed] Seeding Pune Urban Locations...")
    for loc in PUNE_LOCATIONS:
        cursor.execute("""
            INSERT INTO locations (name, ward_code, area_km2, latitude, longitude, description)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                ward_code = excluded.ward_code,
                area_km2 = excluded.area_km2,
                latitude = excluded.latitude,
                longitude = excluded.longitude,
                description = excluded.description;
        """, (loc["name"], loc["ward_code"], loc["area_km2"], loc["latitude"], loc["longitude"], loc["description"]))

    conn.commit()

    # Map name -> location_id
    cursor.execute("SELECT id, name FROM locations;")
    location_map = {row["name"]: row["id"] for row in cursor.fetchall()}

    print("[Seed] Seeding 6 Months of Environmental Observations...")
    # Clear existing observations for idempotent re-run
    cursor.execute("DELETE FROM observations;")

    for loc_name, (base_aqi, base_pm25, base_green, base_temp) in LOCATION_BASELINES.items():
        loc_id = location_map[loc_name]
        for date_str, aqi_mult, pm_mult, green_mult, temp_delta in MONTHS_DATA:
            aqi = int(round(base_aqi * aqi_mult))
            pm25 = round(base_pm25 * pm_mult, 1)
            green = round(min(100.0, base_green * green_mult), 1)
            temp = round(base_temp + temp_delta, 1)

            cursor.execute("""
                INSERT INTO observations (location_id, recorded_date, aqi, pm25, green_cover_pct, surface_temp_c)
                VALUES (?, ?, ?, ?, ?, ?);
            """, (loc_id, date_str, aqi, pm25, green, temp))

    print("[Seed] Seeding Default Urban Planning Recommendations...")
    cursor.execute("DELETE FROM recommendations;")

    # High-Priority and Ward-Specific Recommendations
    pune_recommendations = [
        (
            location_map.get("Swargate"),
            "Clean Transit & Electrification",
            "Bus Terminal Hybridization & Zero-Emission Feeder Network",
            "Swargate transit hub experiences peak hourly PM2.5 exceeding safety by 210%. Reroute regional diesel buses through perimeter electric corridors and install overhead induction charging.",
            "HIGH",
            "₹4.5 Cr",
            "6-12 Months",
            "Reduce particulate hotspot exposure by 35%"
        ),
        (
            location_map.get("Hadapsar"),
            "Industrial Emission Controls",
            "Fabrication Cluster Continuous Stack Monitoring & VOC Scrubbing",
            "Enforce real-time telemetry for small and medium industrial fabrication units in Hadapsar and deploy bio-filters along industrial periphery.",
            "HIGH",
            "₹2.8 Cr",
            "3-6 Months",
            "Cut unpermitted VOC surges and industrial haze"
        ),
        (
            location_map.get("Swargate"),
            "Urban Forestry",
            "Mula-Mutha Riparian Buffer Reforestation",
            "Establish dense continuous 50-meter native riparian green buffer along river embankments to absorb urban runoff and reverse bank degradation.",
            "HIGH",
            "₹2.4 Cr",
            "6-18 Months",
            "NDVI vegetation increase +18% along riverbank"
        ),
        (
            location_map.get("Hinjewadi"),
            "Transit & Microclimate",
            "IT Corridor Shaded Active Mobility & Micro-Canopy Corridors",
            "Develop 12km of shaded non-motorized pedestrian and cycling tracks between Phase 1 and Phase 3 to curb two-wheeler idling emissions.",
            "MEDIUM",
            "₹1.8 Cr",
            "9-15 Months",
            "Reduce localized peak-hour carbon emissions by 14%"
        ),
        (
            location_map.get("Pimpri"),
            "Industrial Emission Controls",
            "Heavy Freight Green Bypass & Truck Idling Curfew",
            "Reroute heavy diesel transport around Pimpri industrial spine via peripheral highway and implement mandatory anti-idling logistics bays.",
            "HIGH",
            "₹3.2 Cr",
            "6-12 Months",
            "Lower ambient PM10 by 24% in residential adjacency"
        ),
        (
            location_map.get("Katraj"),
            "Ecosystem Conservation",
            "Katraj Basin Ecological Buffer & Micro-Sensor Density",
            "Safeguard catchment hills from illegal terrace cutting, preserve lake biodiversity zone, and deploy micro-meteorological sensor nodes.",
            "LOW",
            "₹60 Lakhs",
            "Ongoing",
            "Continuous lake catchment water and air telemetry"
        ),
        (
            location_map.get("Aundh"),
            "Conservation & Replicability",
            "Aundh Model Neighborhood Urban Greening Extension",
            "Maintain benchmark 44% canopy through municipal tree wardens and replicate permeable bioswales across neighboring suburban wards.",
            "LOW",
            "₹45 Lakhs",
            "3-6 Months",
            "Sustained ecological equilibrium"
        ),
        (
            location_map.get("Shivajinagar"),
            "Urban Forestry",
            "Miyawaki Dense Pocket Forests along Transit Nodes",
            "Convert underutilized municipal triangular islands into 4 mini Miyawaki forests with deep native root systems to capture dust.",
            "HIGH",
            "₹95 Lakhs",
            "6 Months",
            "Local particulate reduction & 2.5°C surface cooling"
        ),
        (
            location_map.get("Koregaon Park"),
            "Conservation",
            "Heritage Tree Preservation & Permeable Walkways",
            "Protect 150-year-old banyan canopies through geotagged acoustic tomography and replace cracked asphalt with water-permeable interlocking blocks.",
            "LOW",
            "₹50 Lakhs",
            "Annual",
            "Canopy density preservation >= 45%"
        ),
    ]

    for rec in pune_recommendations:
        cursor.execute("""
            INSERT INTO recommendations (location_id, category, title, description, priority, estimated_cost, time_horizon, target_metric)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """, rec)

    print("[Seed] Seeding Default User Accounts...")
    demo_password_hash = generate_password_hash("Demo@1234")
    admin_password_hash = generate_password_hash("Admin@1234")

    # Seed Demo User (idempotent with INSERT OR IGNORE)
    cursor.execute("""
        INSERT OR IGNORE INTO users (name, email, password_hash, role)
        VALUES (?, ?, ?, ?);
    """, ("Demo Urban Planner", "demo@greengrid.com", demo_password_hash, "user"))

    # Seed Admin User (idempotent with INSERT OR IGNORE)
    cursor.execute("""
        INSERT OR IGNORE INTO users (name, email, password_hash, role)
        VALUES (?, ?, ?, ?);
    """, ("System Administrator", "admin@greengrid.com", admin_password_hash, "admin"))

    conn.commit()

    # Get demo user id
    cursor.execute("SELECT id FROM users WHERE email = 'demo@greengrid.com';")
    demo_user = cursor.fetchone()
    demo_user_id = demo_user["id"] if demo_user else 1

    print("[Seed] Seeding Sample Analysis History for Demo User...")
    cursor.execute("DELETE FROM analysis_results WHERE user_id = ?;", (demo_user_id,))
    
    sample_analyses = [
        (
            demo_user_id,
            location_map.get("Swargate"),
            210.0,
            14.0,
            "HIGH",
            82.4,
            "Compounded high-risk environment: Swargate pollution index of 210 exceeds the critical threshold (150), combined with an acute green canopy deficit (14% vs target 25%). Particulate entrapment is severe."
        ),
        (
            demo_user_id,
            location_map.get("Shivajinagar"),
            175.0,
            22.0,
            "HIGH",
            71.6,
            "Compounded vulnerability: High traffic emissions (AQI 175) and suboptimal tree canopy (22%) create chronic particulate exposure for pedestrians."
        ),
        (
            demo_user_id,
            location_map.get("Hinjewadi"),
            155.0,
            26.0,
            "HIGH",
            63.8,
            "Elevated emission stress: Severe IT commuter congestion causes elevated spikes during morning and evening rush hours."
        ),
        (
            demo_user_id,
            location_map.get("Aundh"),
            82.0,
            44.0,
            "LOW",
            21.2,
            "Ecological equilibrium: Pollution index (82) is safe and green cover (44%) meets urban sustainability benchmarks."
        ),
    ]

    for sa in sample_analyses:
        cursor.execute("""
            INSERT INTO analysis_results (user_id, location_id, pollution_index, green_cover_pct, risk_level, score, explanation)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """, sa)

    conn.commit()
    conn.close()
    print("[Seed] Database seeding completed successfully! Demo account: demo@greengrid.com / Demo@1234")


if __name__ == "__main__":
    seed_database()
