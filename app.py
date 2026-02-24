from itertools import product
from flask import Flask, Response, render_template,  request, redirect, session, flash, url_for
from flask_mail import Mail, Message
import sqlite3
import bcrypt
import random
import config
import os
from werkzeug.utils import secure_filename
from flask import request
from flask import request, jsonify, render_template
import razorpay
import traceback
from flask import make_response, render_template
from utils.pdf_generator import generate_pdf
from flask import send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, render_template, request, redirect, url_for, flash, session
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash
 
import os


serializer = URLSafeTimedSerializer("abcd1234")


import io


ADMIN_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'admin_profiles')

# 🔥 This creates folder automatically if missing
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)


import os
import bcrypt
import uuid
from werkzeug.utils import secure_filename

ADMIN_UPLOAD_FOLDER = os.path.join('static', 'uploads', 'admin_profiles')
os.makedirs(ADMIN_UPLOAD_FOLDER, exist_ok=True)
from itsdangerous import URLSafeTimedSerializer








 
from itsdangerous import URLSafeTimedSerializer
import razorpay

razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)



app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD

mail = Mail(app)


# ---------------- DB CONNECTION FUNCTION --------------

DB_NAME = "smartcart.db"
def get_db_connection():
    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- CREATE TABLES IF NOT EXISTS ----------------
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create admin table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            profile_image TEXT DEFAULT NULL
        )
    ''')
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            profile_image TEXT DEFAULT NULL
        )
    ''')
    
    # Create products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            category TEXT,
            price REAL NOT NULL,
            image TEXT
        )
    ''')
    
    # Create orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            razorpay_order_id TEXT,
            razorpay_payment_id TEXT,
            amount REAL NOT NULL,
            payment_status TEXT DEFAULT 'pending',
            order_status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    # Create order_items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            product_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders (order_id),
            FOREIGN KEY (product_id) REFERENCES products (product_id)
        )
    ''')
    
    # Create address table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS address (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            phone TEXT NOT NULL,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            pincode TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()


# ------------------- IMAGE UPLOAD PATH -------------------
# Use paths from config.py (works for both local and PythonAnywhere)
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['ADMIN_UPLOAD_FOLDER'] = config.ADMIN_UPLOAD_FOLDER

# Create upload directories if they don't exist
os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(config.ADMIN_UPLOAD_FOLDER, exist_ok=True)
if hasattr(config, 'USER_UPLOAD_FOLDER'):
    os.makedirs(config.USER_UPLOAD_FOLDER, exist_ok=True)

# ================= HOME =================
@app.route("/")
def home():
 return redirect(url_for("user_login"))


#---------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------
# ROUTE1 ADMIN SIGNUP PAGE
@app.route('/admin-signup',methods=['GET','POST'])
def admin_signup():
 
    if request.method=="GET":
        return render_template("admin/admin_signup.html")
    
    name=request.form['name']
    email=request.form['email']


    #check if admin email already exists
    conn=get_db_connection()
    cursor=conn.cursor()
    cursor.execute("select admin_id from admin where email=?",(email,))
    existing_admin=cursor.fetchone()
    cursor.close()
    conn.close()

    if existing_admin:
        flash("This email is already registered.please login instead.","danger")
        return render_template('admin/admin_signup.html')
    
    #2 save user input temporarily in session
    session['signup_name']=name
    session['signup_email']=email 


    #3 generate Otp and store in session
    otp=random.randint(100000,999999)
    session['otp']=otp


    #4 send otp email

    message=Message(
        subject="SmartCard Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for PickCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')

# ROUTE 2: DISPLAY OTP PAGE
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['GET'])
def verify_otp_get():
 return render_template("admin/verify_otp.html")
 
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# ---------------------------------------------------------
@app.route('/verify-otp', methods=['POST'])
def verify_otp_post():
 
 # User submitted OTP + Password
 user_otp = request.form['otp']
 password = request.form['password']

 # Compare OTP
 if str(session.get('otp')) != str(user_otp):
  flash("Invalid OTP. Try again!", "danger")
  return redirect('/verify-otp')

 # Hash password using bcrypt
 hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

 # Insert admin into database
 conn = get_db_connection()
 cursor = conn.cursor()
 cursor.execute(
 "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
 (session['signup_name'], session['signup_email'], hashed_password)
 )
 conn.commit()
 cursor.close()
 conn.close()

 # Clear temporary session data
 session.pop('otp', None)
 session.pop('signup_name', None)
 session.pop('signup_email', None)

 flash("Admin Registered Successfully!", "success")
 return redirect('/admin-login')

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()

        admin = conn.execute(
            "SELECT * FROM admin WHERE email=?",
            (email,)
        ).fetchone()

        conn.close()

        if admin:

            if bcrypt.checkpw(password.encode('utf-8'), admin['password']):

                # FIX HERE ↓↓↓
                session['admin_id'] = admin['admin_id']

                flash("Login success", "success")
                return redirect( 'admin/item-list')

            else:
                flash("Wrong password", "danger")

    return render_template("admin/admin_login.html")


# =================================================================
# ROUTE 6: ADMIN LOGOUT
# =================================================================
@app.route('/admin-logout')
def admin_logout():

 # Clear admin session
 session.pop('admin_id', None)
 session.pop('admin_name', None)
 session.pop('admin_email', None)

 flash("Logged out successfully.", "success")
 return redirect('/admin-login')




# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE (Protected Route)
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():

 # Only logged-in admin can access
 if 'admin_id' not in session:
  flash("Please login first!", "danger")
  return redirect('/admin-login')

 return render_template("admin/add_item.html")



# =================================================================
# ROUTE 8: ADD PRODUCT INTO DATABASE
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():

 # Check admin session
 if 'admin_id' not in session:
  flash("Please login first!", "danger")
  return redirect('/admin-login')

 # 1️⃣ Get form data
 name = request.form['name']
 description = request.form['description']
 category = request.form['category']
 price = request.form['price']
 image_file = request.files['image']

 # 2️⃣ Validate image upload
 if image_file.filename == "":
  flash("Please upload a product image!", "danger")
  return redirect('/admin/add-item')

 # 3️⃣ Secure the file name
 filename = secure_filename(image_file.filename)

 # 4️⃣ Create full path
 image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

 # 5️⃣ Save image into folder
 image_file.save(image_path)

 # 6️⃣ Insert product into database
 conn = get_db_connection()
 cursor = conn.cursor()

 cursor.execute(
 "INSERT INTO products (name, description, category, price, image) VALUES (?, ?, ?, ?, ?)",
 (name, description, category, price, filename)
 )

 conn.commit()
 cursor.close()
 conn.close()

 flash("Product added successfully!", "success")
 return redirect('/admin/add-item')

# ROUTE 9: DISPLAY ALL PRODUCTS (Admin)
# =================================================================
@app.route('/admin/item-list')
def item_list():
    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ DEFAULT assignment (IMPORTANT)
    products = []
    categories = []

    # Fetch categories (always)
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    search = request.args.get('search')
    category = request.args.get('category')

    if search:
        query = """
            SELECT * FROM products
            WHERE name LIKE ?
        """
        cursor.execute(query, ('%' + search + '%',))
        products = cursor.fetchall()

    elif category:
        query = """
            SELECT * FROM products
            WHERE category = ?
        """
        cursor.execute(query, (category,))
        products = cursor.fetchall()

    else:
        # ✅ DEFAULT case
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )

#=================================================================
# ROUTE 10: VIEW SINGLE PRODUCT DETAILS
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):

 # Check admin session
 if 'admin_id' not in session:
  flash("Please login first!", "danger")
  return redirect('/admin-login')

 conn = get_db_connection()
 cursor = conn.cursor()

 cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
 product = cursor.fetchone()

 cursor.close()
 conn.close()

 if not product:
  flash("Product not found!", "danger")
  return redirect('/admin/item-list')

 return render_template("admin/view_item.html", product=product)

# =================================================================
# ROUTE 11: SHOW UPDATE FORM WITH EXISTING DATA
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):

 # Check login
 if 'admin_id' not in session:
  flash("Please login!", "danger")
  return redirect('/admin-login')

 # Fetch product data
 conn = get_db_connection()
 cursor = conn.cursor()

 cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
 product = cursor.fetchone()

 cursor.close()
 conn.close()

 if not product:
  flash("Product not found!", "danger")
  return redirect('/admin/item-list')

 return render_template("admin/update_item.html", product=product)



@app.route("/admin/update-item/<int:item_id>", methods=["POST"])
def update_item(item_id):

    if "admin_id" not in session:
        return redirect("/admin-login")

    name = request.form["name"]
    price = request.form["price"]
    category = request.form["category"]

    new_image = request.files["image"]

    con = get_db_connection()
    cur = con.cursor()

    # ✅ FIX HERE
    cur.execute(
        "SELECT image FROM products WHERE product_id=?",
        (item_id,)
    )

    product = cur.fetchone()

    filename = product["image"]

    if new_image and new_image.filename != "":
        filename = secure_filename(new_image.filename)

        path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            filename
        )

        new_image.save(path)

    # ✅ FIX HERE ALSO
    cur.execute("""
        UPDATE products
        SET name=?, price=?, category=?, image=?
        WHERE product_id=?
    """, (name, price, category, filename, item_id))

    con.commit()

    cur.close()
    con.close()

    flash("Product updated successfully", "success")

    return redirect("/admin/item-list")



@app.route('/about')
def about():
 return (render_template('about.html'))

 
@app.route('/contact')
def contact():
 return (render_template('contact.html'))


# =================================================================
#Route 13: DELETE PRODUCT (DELETE DB ROW + DELETE IMAGE FILE)
# =================================================================
@app.route('/admin/delete-item/<int:item_id>')
def delete_item(item_id):

 if 'admin_id' not in session:
  flash("Please login first!", "danger")
  return redirect('/admin-login')

 conn = get_db_connection()
 cursor = conn.cursor()

 # 1️⃣ Fetch product to get image name
 cursor.execute("SELECT image FROM products WHERE product_id=?", (item_id,))
 product = cursor.fetchone()

 if not product:
  flash("Product not found!", "danger")
  return redirect('/admin/item-list')

 image_name = product['image']

 # Delete image from folder
 image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_name)
 if os.path.exists(image_path):
  os.remove(image_path)

 # 2️⃣ Delete product from DB
 cursor.execute("DELETE FROM products WHERE product_id=?", (item_id,))
 conn.commit()

 cursor.close()
 conn.close()

 flash("Product deleted successfully!", "success")
 return redirect('/admin/item-list')


# =================================================================
# ROUTE 14: SHOW ADMIN PROFILE DATA
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():

 if 'admin_id' not in session:
  flash("Please login!", "danger")
  return redirect('/admin-login')

 admin_id = session['admin_id']

 conn = get_db_connection()
 cursor = conn.cursor()

 cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
 admin = cursor.fetchone()

 cursor.close()
 conn.close()

 return render_template("admin/admin_profile.html", admin=admin)


# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE (NAME, EMAIL, PASSWORD, IMAGE)
# =================================================================
@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile_update():

    if 'admin_id' not in session:
        flash("Please login first", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get current admin data
    cursor.execute("SELECT * FROM admin WHERE admin_id=?",
                   (session['admin_id'],))
    admin = cursor.fetchone()

    if request.method == 'POST':

        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        new_image = request.files.get('profile_image')

        # 🔹 Update name & email
        cursor.execute("""
            UPDATE admin 
            SET name=?, email=? 
            WHERE admin_id=?
        """, (name, email, session['admin_id']))

        # 🔹 Update password (if provided)
        if password:
            hashed_password = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt()
            )
            cursor.execute("""
                UPDATE admin 
                SET password=? 
                WHERE admin_id=?
            """, (hashed_password, session['admin_id']))

        # 🔹 Update profile image (if uploaded)
        if new_image and new_image.filename != "":

            # Delete old image if exists
            if admin['profile_image']:
                old_image_path = os.path.join(
                    ADMIN_UPLOAD_FOLDER,
                    admin['profile_image']
                )

                if os.path.exists(old_image_path):
                    os.remove(old_image_path)

            # Save new image with unique name
            filename = str(uuid.uuid4()) + "_" + secure_filename(new_image.filename)
            image_path = os.path.join(ADMIN_UPLOAD_FOLDER, filename)
            new_image.save(image_path)

            cursor.execute("""
                UPDATE admin 
                SET profile_image=? 
                WHERE admin_id=?
            """, (filename, session['admin_id']))

        conn.commit()
        flash("Profile updated successfully!", "success")

        return redirect('/admin/profile')

    cursor.close()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

#=================================================================
# ROUTE: ADMIN PRODUCT LISTING (SEARCH + FILTER)
# (Combined with item_list function above)
# =================================================================



# =================================================================
# ROUTE: USER REGISTRATION
# =================================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():

    if request.method == 'GET':
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Check if user already exists
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        flash("Email already registered! Please login.", "danger")
        return redirect('/user-register')

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Insert new user
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (name, email, hashed_password)
    )
    conn.commit()

    cursor.close()
    conn.close()

    flash("Registration successful! Please login.", "success")
    return redirect('/user-login')

# =================================================================
# ROUTE: USER LOGIN
# =================================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():

    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user:
        flash("Email not found! Please register.", "danger")
        return redirect('/user-login')

    # Verify password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    # Create user session
    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login successful!", "success")
    return redirect('/user/products')


# =================================================================
# ROUTE: USER DASHBOARD
# =================================================================
@app.route('/user-dashboard')
def user_dashboard():

 if 'user_id' not in session:
  flash("Please login first!", "danger")
  return redirect('/user-login')

 return render_template("user/user_products.html", user_name=session['user_name'])

#=================================================================
# ROUTE: USER PRODUCT LISTING (SEARCH + FILTER)
# =================================================================


@app.route('/user/products', methods=["GET"])
def user_products():

    # check login
    if "user_id" not in session:
        return redirect("/user-login")

    search = request.args.get("search", "")
    category = request.args.get("category", "")

    con = get_db_connection()
    cur = con.cursor()

    # base query
    query = "SELECT * FROM products WHERE 1=1"
    values = []

    # search filter
    if search:
        query += " AND name LIKE ?"
        values.append("%" + search + "%")

    # category filter
    if category:
        query += " AND category=?"
        values.append(category)

    cur.execute(query, values)
    products = cur.fetchall()

    # categories for dropdown
    cur.execute("SELECT DISTINCT category FROM products")
    categories = cur.fetchall()

    cur.close()
    con.close()

    return render_template(
        "user/user_products.html",
        products=products,
        categories=categories,
        search=search,
        selected_category=category
    )


@app.route('/profile', methods=['GET','POST'])
def user_profile():

    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    upload_folder = config.USER_UPLOAD_FOLDER
    os.makedirs(upload_folder, exist_ok=True)


    if request.method == 'POST':

        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        image = request.files.get('profile_image')


        # ================= IMAGE UPDATE =================

        if image and image.filename != "":

            filename = secure_filename(image.filename)

            image.save(os.path.join(upload_folder, filename))

            cursor.execute("""
                UPDATE users
                SET profile_image=?
                WHERE user_id=?
            """, (filename, session['user_id']))



        # ================= PASSWORD UPDATE =================

        if password:

            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            cursor.execute("""
                UPDATE users
                SET password=?
                WHERE user_id=?
            """, (hashed, session['user_id']))



        # ================= NAME EMAIL UPDATE =================

        cursor.execute("""
            UPDATE users
            SET name=?, email=?
            WHERE user_id=?
        """, (name, email, session['user_id']))


        conn.commit()



    # ================= GET USER =================

    cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))

    user = cursor.fetchone()


    cursor.close()
    conn.close()


    return render_template("user/profile.html", user=user)




# =================================================================
# ROUTE: USER PRODUCT DETAILS PAGE
# =================================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):

    # 🔐 Allow only logged-in users
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔍 Fetch product details
    cursor.execute(
        "SELECT * FROM products WHERE product_id = ?",
        (product_id,)
    )
    product = cursor.fetchone()

    cursor.close()
    conn.close()

    # ❌ If product does not exist
    if not product:
        flash("Product not found!", "danger")
        return redirect('/user/products')
    
    # flash("Profile Updated Successfully!", "success")


    return render_template(
        "user/product_details.html",
        product=product
    )





# =================================================================
# ROUTE: USER LOGOUT
# =================================================================
@app.route('/user-logout')
def user_logout():
 
 session.pop('user_id', None)
 session.pop('user_name', None)
 session.pop('user_email', None)

 flash("Logged out successfully!", "success")
 return redirect('/user-login')

# =================================================================
# ADD ITEM TO CART
# =================================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    # Create cart if doesn't exist
    if 'cart' not in session:
        session['cart'] = {}

    cart = session['cart']

    # Get product
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        flash("Product not found.", "danger")
        return redirect(request.referrer)

    pid = str(product_id)

    # If exists → increase quantity
    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart

    flash("Item added to cart!", "success")
    return redirect(request.referrer)





# =================================================================
# VIEW CART PAGE
# =================================================================
@app.route('/user/cart')
def view_cart():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    # Calculate total
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)

# =================================================================
# INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] += 1

    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart[pid]['quantity'] -= 1

        # If quantity becomes 0 → remove item
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)

    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):

    cart = session.get('cart', {})

    if pid in cart:
        cart.pop(pid)

    session['cart'] = cart

    flash("Item removed!", "success")
    return redirect('/user/cart')

# =================================================================
# ROUTE: CREATE RAZORPAY ORDER
# =================================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})

    if not cart:
        flash("Your cart is empty!", "danger")
        return redirect('/user/products')

    # Calculate total amount
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())
    razorpay_amount = int(total_amount * 100)  # convert to paise

    # Create Razorpay order
    razorpay_order = razorpay_client.order.create({
        "amount": razorpay_amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        amount=total_amount,
        key_id=config.RAZORPAY_KEY_ID,
        order_id=razorpay_order['id']
    )
@app.route('/payment')
def payment():

    cart = session.get('cart', {})
    if not cart:
        flash("Cart is empty!", "error")
        return redirect('/products')

    total = 0

    conn = get_db_connection()
    cursor = conn.cursor()

    for pid, item in cart.items():

        cursor.execute(
            "SELECT price FROM products WHERE product_id=?",
            (pid,)
        )

        result = cursor.fetchone()

        if not result:
            continue

        price = float(result[0])

        # ✅ SUPER SAFE quantity handling
        if isinstance(item, dict):
            quantity = int(item.get('qty', 1))
        else:
            quantity = int(item)

        total += price * quantity

    cursor.close()
    conn.close()

    order = razorpay_client.order.create({
        "amount": int(total * 100),
        "currency": "INR",
        "payment_capture": 1
    })

    return render_template(
        "user/payment.html",
        amount=total,
        order_id=order['id'],
        key_id="rzp_test_SFXKBUvo0xSUpI"
    )

 
# =================================================================
# TEMP SUCCESS PAGE (Verification in Day 13)
# =================================================================
@app.route('/payment-success')
def payment_success():

    payment_id = request.args.get('payment_id')
    order_id = request.args.get('order_id')

    if not payment_id:
        flash("Payment failed!", "danger")
        return redirect('/user/cart')

    return render_template(
        "user/payment_success.html",
        payment_id=payment_id,
        order_id=order_id
    )

# ------------------------------
# Route: Verify Payment and Store Order
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():
    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    # Read values posted from frontend
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    # Build verification payload required by Razorpay client.utility
    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        # This will raise an error if signature invalid
        razorpay_client.utility.verify_payment_signature(payload)

    except Exception as e:
        # Verification failed
        app.logger.error("Razorpay signature verification failed: %s", str(e))
        flash("Payment verification failed. Please contact support.", "danger")
        return redirect('/user/cart')

    # Signature verified — now store order and items into DB
    user_id = session['user_id']
    cart = session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    # Calculate total amount (ensure same as earlier)
    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    # DB insert: orders and order_items
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert into orders table
        cursor.execute("""
            INSERT INTO orders (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, razorpay_order_id, razorpay_payment_id, total_amount, 'paid'))

        order_db_id = cursor.lastrowid  # newly created order's primary key

        # Insert all items
        for pid_str, item in cart.items():
            product_id = int(pid_str)
            cursor.execute("""
                INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (order_db_id, product_id, item['name'], item['quantity'], item['price']))

        # Commit transaction
        conn.commit()

        # Clear cart and temporary razorpay order id
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        # Rollback and log error
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("There was an error saving your order. Contact support.", "danger")
        return redirect('/user/cart')
    
    finally:
        cursor.close()
        conn.close()

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):
    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE order_id=? AND user_id=?", (order_db_id, session['user_id']))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_db_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    if not order:
        flash("Order not found.", "danger")
        return redirect('/user/products')

    return render_template("user/order_success.html", order=order, items=items)

@app.route('/my-orders')
def my_orders():

    if 'user_id' not in session:
        return redirect('/login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT order_id,
       amount,
       order_status,
       payment_status
       FROM orders
       WHERE user_id=?
       ORDER BY order_id DESC
       """,(session['user_id'],))




    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
import io


def generate_pdf_bytes(order, items):

    buffer = io.BytesIO()

    pdf = SimpleDocTemplate(
        buffer,
        pagesize=(8.5 * inch, 11 * inch),
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    elements = []

    emerald = HexColor("#27ae60")

    styles = getSampleStyleSheet()

    # ✅ Title Style
    title_style = ParagraphStyle(
        name="Title",
        fontSize=26,
        textColor=emerald,
        alignment=1,
        spaceAfter=30
    )

    # ✅ Normal Style Bigger
    normal = ParagraphStyle(
        name="Normal",
        fontSize=13,
        spaceAfter=6
    )


    # ✅ Title
    elements.append(Paragraph("<b>SMARTCART INVOICE</b>", title_style))


    # ✅ Order Details
    elements.append(Paragraph(f"<b>Order ID:</b> {order['order_id']}", normal))

    elements.append(Paragraph(f"<b>Total Amount:</b> ₹{order['amount']}", normal))

    elements.append(Paragraph(f"<b>Payment Status:</b> {order['payment_status']}", normal))

    elements.append(Paragraph(f"<b>Date:</b> {order['created_at']}", normal))


    elements.append(Spacer(1, 30))


    # ✅ Table Data
    data = [["Product", "Price", "Quantity", "Total"]]

    grand_total = 0

    for item in items:

        total = item['price'] * item['quantity']

        grand_total += total

        data.append([
            item['name'],
            f"₹{item['price']}",
            item['quantity'],
            f"₹{total}"
        ])


    data.append(["", "", "Grand Total", f"₹{grand_total}"])


    # ✅ FULL WIDTH TABLE
    table = Table(data, colWidths=[250, 100, 100, 120])


    table.setStyle(TableStyle([

        ("BACKGROUND", (0, 0), (-1, 0), emerald),

        ("TEXTCOLOR", (0, 0), (-1, 0), white),

        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),

        ("FONTSIZE", (0, 0), (-1, -1), 12),

        ("GRID", (0, 0), (-1, -1), 1, black),

        ("ALIGN", (1, 1), (-1, -1), "CENTER"),

        ("BACKGROUND", (0, -1), (-1, -1), HexColor("#d5f5e3")),

        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),

    ]))


    elements.append(table)


    elements.append(Spacer(1, 50))


    # ✅ Footer
    footer = ParagraphStyle(
        name="Footer",
        fontSize=14,
        alignment=1,
        textColor=emerald
    )

    elements.append(Paragraph(
        "<b>Thank you for shopping with SMARTCART</b>",
        footer
    ))


    pdf.build(elements)

    buffer.seek(0)

    return buffer


@app.route("/download_invoice/<int:order_id>")
def download_invoice(order_id):

    conn = sqlite3.connect(config.DB_NAME)
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()


    # ✅ ONLY YOUR 4 COLUMNS
    cursor.execute("""

        SELECT 
            order_id,
            amount,
            payment_status,
            created_at

        FROM orders

        WHERE order_id = ?

    """, (order_id,))


    order = cursor.fetchone()



    cursor.execute("""

        SELECT 
            p.name,
            oi.quantity,
            oi.price

        FROM order_items oi

        JOIN products p ON oi.product_id = p.product_id

        WHERE oi.order_id = ?

    """, (order_id,))


    items = cursor.fetchall()


    cursor.close()

    conn.close()


    pdf = generate_pdf_bytes(order, items)


    return send_file(

        pdf,

        as_attachment=True,

        download_name=f"SMARTCART_invoice_{order_id}.pdf",

        mimetype="application/pdf"

    )

@app.route("/user/address", methods=["GET", "POST"])
def add_address():

    if request.method == "POST":

        fullname = request.form["fullname"]

        phone = request.form["phone"]

        address = request.form["address"]

        city = request.form["city"]

        pincode = request.form["pincode"]


        conn = sqlite3.connect(config.DB_NAME)

        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO address 
            (fullname, phone, address, city, pincode)
            VALUES (?,?,?,?,?)
        """, (fullname, phone, address, city, pincode))

        conn.commit()

        cursor.close()
        conn.close()


        flash("Address saved successfully", "success")

        return redirect(url_for("payment"))


    return render_template("user/address.html")

# ================================================================
# ADMIN: VIEW ORDER DETAILS
# ================================================================
@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM orders WHERE order_id=?", (order_id,))
    order = cursor.fetchone()

    cursor.execute("SELECT * FROM order_items WHERE order_id=?", (order_id,))
    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("admin/order_details.html", order=order, items=items)

# ================================================================
# ADMIN: UPDATE ORDER STATUS
# ================================================================
@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):
    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE orders SET order_status=? WHERE order_id=?",
                    (new_status, order_id))

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")


from flask import Flask, render_template, session, redirect, url_for, flash

@app.route("/user/order/<int:order_id>")
def user_order_details(order_id):

    # Check user login
    user_id = session.get("user_id")
    if not user_id:
        flash("Please login to view your orders.", "warning")
        return redirect(url_for("login"))

    # Get database connection
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch order
        cursor.execute(
            "SELECT * FROM orders WHERE order_id=? AND user_id=?",
            (order_id, user_id)
        )
        order = cursor.fetchone()

        if not order:
            flash("Order not found or access denied.", "danger")
            return redirect(url_for("user_orders"))

        # Fetch order items
        cursor.execute("""
            SELECT oi.*, p.name, p.image, p.price
            FROM order_items oi
            JOIN products p ON p.product_id = oi.product_id
            WHERE oi.order_id=?
        """, (order_id,))
        items = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template("user/order_details.html", order=order, items=items)

@app.route("/user/orders")
def user_orders():

    user_id = session.get("user_id")

    if not user_id:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM orders
        WHERE user_id=?
        ORDER BY order_id DESC
    """, (user_id,))

    orders = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("user/orders.html", orders=orders)



  
@app.route("/forgot-password", methods=["GET", "POST"])
def user_forgot_password():
   
   
     
   if request.method == "POST":
    email = request.form["email"]


 # Generate reset token
    token = serializer.dumps(email, salt="reset-password")

    link = url_for("user_reset_password", token=token, _external=True)



     # Generate reset token
 

 # Send email
    msg = Message(
       "Password Reset",
        sender=app.config["MAIL_USERNAME"],
        recipients=[email]
    )
    msg.body = f"Click the link below to reset your password:\n{link}"
    mail.send(msg)
    flash("Reset link sent to your email")
    return redirect(url_for("user_forgot_password"))
   return render_template("user/forgot_password.html")

 

# ================= USER RESET PASSWORD =================
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def user_reset_password(token):
    try:
     email = serializer.loads(token, salt="reset-password", max_age=3600)
    except:
        flash("Invalid or expired link")
        return redirect(url_for("user_forgot_password"))

    if request.method == "POST":
     new_password = request.form["password"]
 # TODO: Update the password in your database for this email
     flash("Password updated successfully")
     return redirect(url_for("user_login"))
    return render_template("user/reset_password.html")





if __name__=='__main__':
 app.run(debug=True)
