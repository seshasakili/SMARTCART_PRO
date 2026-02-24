import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "smartcart.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "schema.sql")

def init_db():
    with sqlite3.connect(DATABASE) as conn:
     with open(SCHEMA_PATH, "r") as f:
      conn.executescript(f.read())
    print("Database initialized successfully!")

if __name__ == "__main__":
 init_db()