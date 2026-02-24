# ------------------------------------
# SMARTCART_PRO CONFIG FILE (SQLite3)
# ------------------------------------

import os

# Base directory
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ---------------- SECRET KEY ----------------

SECRET_KEY = "abcd1234"


# ---------------- SQLITE DATABASE ----------------
# This will create smartcart.db in your project folder

DB_NAME = os.path.join(BASE_DIR, "smartcart.db")


# ---------------- UPLOAD FOLDERS ----------------

UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "products")

ADMIN_UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "admin_profiles")

USER_UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads", "user_profiles")


# ---------------- EMAIL CONFIG ----------------

MAIL_SERVER = "smtp.gmail.com"

MAIL_PORT = 587

MAIL_USE_TLS = True

MAIL_USERNAME = "seshasakili@gmail.com"

MAIL_PASSWORD = "srtd biic gigg nsnv"


# ---------------- RAZORPAY CONFIG ----------------

RAZORPAY_KEY_ID = "rzp_test_SFXKBUvo0xSUpI"

RAZORPAY_KEY_SECRET = "39iP0wQaPqTlwXIjShCqoITB"