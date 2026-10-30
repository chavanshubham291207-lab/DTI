"""
GREEN GRID - Database Module
Provides SQLite database connection management, table schemas, and indexing.
Uses parameterized queries to ensure security.
"""

import os
import sqlite3
from pathlib import Path
from dotenv import load_dotenv

# Load environment configuration
backend_dir = Path(__file__).resolve().parent
load_dotenv(backend_dir / ".env")

DB_NAME = os.getenv("DB_PATH", "greengrid.db")
DB_FILE = backend_dir / DB_NAME


def get_db():
    """
    Get a connection to the SQLite database with Row factory enabled
    so columns can be accessed by name.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """
    Initialize database tables and create indexes if they don't already exist.
    """
    conn = get_db()
    cursor = conn.cursor()

    # 1. Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Locations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        ward_code TEXT,
        area_km2 REAL,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Observations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        location_id INTEGER NOT NULL,
        recorded_date TEXT NOT NULL,
        aqi INTEGER NOT NULL,
        pm25 REAL NOT NULL,
        green_cover_pct REAL NOT NULL,
        surface_temp_c REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
    );
    """)

    # 4. Analysis Results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        location_id INTEGER NOT NULL,
        pollution_index REAL NOT NULL,
        green_cover_pct REAL NOT NULL,
        risk_level TEXT NOT NULL,
        score REAL NOT NULL,
        explanation TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
    );
    """)

    # 5. Recommendations table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recommendations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        location_id INTEGER,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        priority TEXT NOT NULL,
        estimated_cost TEXT,
        time_horizon TEXT,
        target_metric TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
    );
    """)

    # Performance & Lookup Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_obs_location ON observations(location_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_obs_date ON observations(recorded_date);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_user ON analysis_results(user_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_location ON analysis_results(location_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_recs_location ON recommendations(location_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_recs_priority ON recommendations(priority);")

    conn.commit()
    conn.close()
    print(f"[Database] SQLite schema verified and ready at: {DB_FILE}")


if __name__ == "__main__":
    init_db()
