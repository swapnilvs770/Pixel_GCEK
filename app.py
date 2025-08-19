from werkzeug.security import generate_password_hash
import math
from oauth_drive_utils import fetch_images_from_drive, extract_folder_id
from imagekitio.models.UploadFileRequestOptions import UploadFileRequestOptions
from imagekitio import ImageKit
from PIL import Image
from flask import Flask, render_template, request, redirect, url_for, flash
import json
from calendar import c
import os
from datetime import datetime, date  # Ensure date is imported
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
from io import BytesIO
import random
import secrets
import smtplib
from datetime import timedelta
from sqlite3 import Cursor

import bcrypt
import mysql.connector
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    send_file,
    url_for,
)
from mysql.connector import cursor
from reportlab.lib.pagesizes import A4, letter
from reportlab.pdfgen import canvas
from werkzeug.utils import secure_filename

# Import Flask-SQLAlchemy
from flask_sqlalchemy import SQLAlchemy  # <--- ADD THIS LINE

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv()


app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "a_default_secret_key_if_not_set")


# Database Configuration (for direct mysql.connector connections)
db_config_mysql = {  # <--- RENAMED to avoid confusion
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DATABASE", "pixel_db"),
}

# --- NEW: Flask-SQLAlchemy Setup ---
db = SQLAlchemy()  # <--- Initialize SQLAlchemy instance

# Construct the SQLAlchemy URI from your existing db_config_mysql
# This is how Flask-SQLAlchemy knows how to connect
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+mysqlconnector://{db_config_mysql['user']}:{db_config_mysql['password']}@"
    f"{db_config_mysql['host']}/{db_config_mysql['database']}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Recommended to disable

db.init_app(app)  # <--- Initialize SQLAlchemy with your Flask app
# --- END NEW: Flask-SQLAlchemy Setup ---


# SMTP Configuration (Email Setup)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "your_email@gmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "your_app_password")

# Add configuration for uploads
UPLOAD_FOLDER = "static/uploads/gallery"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Function to establish a database connection (for mysql.connector, if you still use it)
def get_db_connection():
    # <--- Using the renamed dict
    return mysql.connector.connect(**db_config_mysql)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Access denied. Please log in as admin.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)

    return decorated_function


def pixel_head_or_member_required(f):
    """
    Decorator to restrict access to Pixel Head or Pixel Member roles.
    Redirects unauthorized users or returns a 403 Forbidden.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            # If not logged in, redirect to login page or return unauthorized
            # Assuming your login route is 'login'
            flash("You need to be logged in to access this page.", "warning")
            # Or return jsonify({"status": "error", "message": "Unauthorized"}), 401
            return redirect(url_for("login"))

        role = session.get("admin_role")
        if role not in ["super_admin", "co_admin"]:  # Using existing session roles
            # If the role is neither Pixel Head (super_admin) nor Pixel Member (co_admin)
            flash("You do not have permission to access this page.", "danger")
            # Redirect to a safe page, e.g., dashboard
            return redirect(url_for("admin_dashboard"))
            # Or for API endpoints, return a JSON error:
            # return jsonify({"status": "error", "message": "Forbidden: Insufficient permissions"}), 403
        return f(*args, **kwargs)
    return decorated_function


def pixel_head_required(f):
    """
    Decorator to restrict access to Pixel Head or Pixel Member roles.
    Redirects unauthorized users or returns a 403 Forbidden.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            # If not logged in, redirect to login page or return unauthorized
            # Assuming your login route is 'login'
            flash("You need to be logged in to access this page.", "warning")
            # Or return jsonify({"status": "error", "message": "Unauthorized"}), 401
            return redirect(url_for("admin_login"))

        role = session.get("admin_role")
        if role not in ["super_admin"]:  # Using existing session roles
            # If the role is neither Pixel Head (super_admin) nor Pixel Member (co_admin)
            flash("You do not have permission to access this page.", "danger")
            # Redirect to a safe page, e.g., dashboard
            return redirect(url_for("admin_dashboard"))

        return f(*args, **kwargs)
    return decorated_function

# Token-based security setup (place this right after app.secret_key)


def generate_token():
    return secrets.token_urlsafe(16)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Please log in first.", "warning")
            return redirect(url_for("admin_login"))

        # For POST requests, check token from form data or URL
        if request.method == "POST":
            token = request.form.get("token") or request.args.get("token")
            if not token or token != session.get("url_token"):
                flash("Invalid security token", "danger")
                return redirect(url_for("admin_login"))

        return f(*args, **kwargs)

    return decorated


@app.route("/")
def index():
    # Load albums
    with open("gallery.json", "r") as f:
        albums = json.load(f)

    # Fetch team members
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, name, role, photo
        FROM login
        WHERE role IN ('super_admin', 'co_admin', 'faculty_advisor')
        ORDER BY role ASC
    """)
    team_members = cursor.fetchall()
    cursor.close()
    db.close()

    return render_template("index.html", albums=albums, team_members=team_members)


import bcrypt
from werkzeug.security import check_password_hash

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        if "login_token" not in session:
            session["login_token"] = secrets.token_urlsafe(16)
        return render_template("admin_login.html", login_token=session["login_token"])

    if request.method == "POST":
        if not request.form.get("login_token") or request.form.get("login_token") != session.get("login_token"):
            flash("Invalid security token", "error")
            session["login_token"] = secrets.token_urlsafe(16)
            return render_template("admin_login.html", login_token=session["login_token"])

        username = request.form["username"]
        password = request.form["password"]

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM login WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if user:
            stored_hash = user["password"]

            if not stored_hash:
                flash("No password hash stored for this user.", "error")
                return render_template("admin_login.html", login_token=session.get("login_token"))

            authenticated = False
            try:
                if stored_hash.startswith("$2b$"):
                    # bcrypt
                    authenticated = bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
                else:
                    # werkzeug (scrypt, pbkdf2)
                    authenticated = check_password_hash(stored_hash, password)
            except Exception as e:
                flash("Invalid password hash in database.", "error")
                return render_template("admin_login.html", login_token=session.get("login_token"))

            if authenticated:
                session.pop("login_token", None)
                session["auth_token"] = secrets.token_urlsafe(32)
                session["admin_logged_in"] = True
                session["admin_username"] = user["username"]
                session["admin_role"] = user.get("role", "co_admin")
                return redirect(url_for("admin_dashboard", username=username, token=session["auth_token"]))
            else:
                flash("Invalid credentials.", "error")
                return render_template("admin_login.html", login_token=session.get("login_token"))
        else:
            flash("Invalid credentials.", "error")
            return render_template("admin_login.html", login_token=session.get("login_token"))


@app.route("/admin_dashboard")
@admin_required
@token_required
def admin_dashboard():
    if "url_token" not in session:
        session["url_token"] = generate_token()

    if not session.get("admin_logged_in"):
        flash("Please log in first.", "warning")
        return redirect(url_for("admin_login"))

    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor(dictionary=True)

        current_date = datetime.now().strftime("%Y-%m-%d")

        # Delete old requests
        cursor.execute(
            "DELETE FROM permission_requests WHERE request_date < %s", (current_date,))
        db_conn.commit()

        # Fetch all required columns for detailed approval status display
        cursor.execute(
            """
            SELECT id, user_name, club, request_date,request_time, location, contact_no, status,
                   email_id, Clg_Mail,
                   pixel_member_approval_status, pixel_member_approval_by, pixel_member_approval_time,
                   pixel_head_approval_status, pixel_head_approval_by, pixel_head_approval_time,
                   faculty_advisor_approval_status, faculty_advisor_approval_by, faculty_advisor_approval_time,
                   email_notification_status
            FROM permission_requests
            WHERE request_date >= %s
            ORDER BY FIELD(status, 'accepted', 'pending', 'rejected'), request_date ASC
        """,
            (current_date,),
        )
        requests = cursor.fetchall()

        cursor.close()
        db_conn.close()

        return render_template(
            "admin_dashboard.html",

            requests=requests,
            token=session["url_token"],
            admin_role=session.get("admin_role", "co_admin"),
            # Ensure default for safety
            admin_username=session.get("admin_username", "Admin"),
        )

    except mysql.connector.Error as e:
        flash("Database error: " + str(e), "danger")
        return redirect(url_for("admin_login"))


@app.route("/admin_logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


@app.route("/add_coadmin", methods=["GET", "POST"])
@pixel_head_required
@admin_required
def add_coadmin():
    if session.get("admin_role") != "super_admin":
        flash("Only Super Admins can add Admins.", "danger")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        name = request.form["name"]
        username = request.form["username"]
        email = request.form["email"]
        password_raw = request.form["password"]
        role = request.form["role"]
        photo = request.files["photo"]

        # Validate
        if not photo or '.' not in photo.filename or \
                photo.filename.rsplit('.', 1)[1].lower() not in ALLOWED_EXTENSIONS:
            flash("Invalid photo file.", "danger")
            return redirect(request.url)

        # Save photo
        filename = secure_filename(username + "_" + photo.filename)
        photo_path = os.path.join(UPLOAD_FOLDER, filename)
        photo.save(photo_path)

        # Hash password
        password_hashed = generate_password_hash(password_raw)

        # Insert into DB
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO login (name, username, password, role, email, photo) VALUES (%s, %s, %s, %s, %s, %s)",
            (name, username, password_hashed, role, email, filename)
        )

        db.commit()
        cursor.close()
        db.close()

        # Send email
        send_admin_email(email, username, password_raw, role)

        flash("Admin added successfully ✅", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template("add_coadmin.html")

from email.mime.text import MIMEText

def send_admin_email(to_email, username, password, role):
    sender_email = SENDER_EMAIL
    sender_password = SENDER_PASSWORD
    smtp_server = SMTP_SERVER
    smtp_port = 465  # SSL port

    subject = "Your Admin Account Created"
    body = f"""
    Hello {username},

    Your admin account has been created.

    Username: {username}
    Password: {password}
    Role: {role}

    Please log in and change your password.

    Thank you.
    - Team Pixel Club
    """

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = to_email
    print("Sending email to:", to_email)

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print("Email sent successfully.")
    except Exception as e:
        print("Error sending email:", e)


@app.route("/admin_change_password", methods=["POST"])
@pixel_head_required
def change_password():
    data = request.get_json()
    email = data.get("email") 
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not email or not old_password or not new_password:
        return jsonify({"success": False, "message": "All fields are required."})

    db = get_db_connection()
    cursor = db.cursor()

    # Fetch user by email
    cursor.execute("SELECT id, password FROM login WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        db.close()
        return jsonify({"success": False, "message": "Email not found."})

    stored_hashed_password = user[1]

    # Check old password
    if not bcrypt.checkpw(old_password.encode("utf-8"), stored_hashed_password.encode("utf-8")):
        cursor.close()
        db.close()
        return jsonify({"success": False, "message": "Old password is incorrect."})

    # Hash new password
    salt = bcrypt.gensalt()
    new_password_hashed = bcrypt.hashpw(new_password.encode("utf-8"), salt).decode("utf-8")

    # Update
    cursor.execute(
        "UPDATE login SET password = %s WHERE email = %s",
        (new_password_hashed, email)
    )
    db.commit()
    cursor.close()
    db.close()

    return jsonify({"success": True})


@app.route("/view_admins")

@admin_required
def view_admins():
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, username, email, role, photo FROM login WHERE role IN ('super_admin', 'co_admin')"
    )
    admins = cursor.fetchall()
    cursor.close()
    db.close()

    current_role = session.get("admin_role")  # e.g., "super_admin"
    return render_template("view_admins.html", admins=admins, current_role=current_role)


@app.route("/appoint_head/<int:admin_id>", methods=["POST"])
@pixel_head_required
def appoint_head(admin_id):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE login SET role='super_admin' WHERE id=%s", (admin_id,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"success": True})

@app.route("/change_photo/<int:admin_id>", methods=["POST"])
@pixel_head_required
def change_photo(admin_id):
    if 'photo' not in request.files:
        return jsonify({"success": False, "message": "No file uploaded."})
    photo = request.files['photo']
    filename = secure_filename(photo.filename)
    photo.save(os.path.join('static/uploads', filename))
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE login SET photo=%s WHERE id=%s", (filename, admin_id))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"success": True})

@app.route("/change_password_direct/<int:admin_id>", methods=["POST"])
@pixel_head_required
def change_password_direct(admin_id):
    data = request.get_json()
    new_password = data["new_password"]
    hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("UPDATE login SET password=%s WHERE id=%s", (hashed, admin_id))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"success": True})

@app.route('/delete_admin/<int:admin_id>', methods=['POST'])
@pixel_head_required
@admin_required
def delete_admin(admin_id):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("DELETE FROM login WHERE id = %s", (admin_id,))
    db.commit()
    cursor.close()
    db.close()
    return jsonify({"success": True, "message": "Admin deleted."})


def generate_approval_pdf(applicant_name, club_committee, contact_no, event_name, event_date_time, location):
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    pdf.setFont("Helvetica", 10)

    # Header
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(50, 790, "PIXEL CLUB - EVENT COVERAGE APPROVAL")

    # Date
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, 760, f"Date: {datetime.now().strftime('%Y-%m-%d')}")

    # Applicant Details
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, 720, "Applicant Details")
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, 705, f"Name: {applicant_name}")
    pdf.drawString(50, 690, f"Club Committee: {club_committee}")
    pdf.drawString(50, 675, f"Contact No.: {contact_no}")

    # Approval Text
    pdf.drawString(
        50, 645, "This letter confirms that the Pixel Club has approved your request to cover")
    pdf.drawString(50, 630, "the below mentioned event.")
    pdf.drawString(50, 600, "Our designated photographers and videographers")
    pdf.drawString(
        50, 585, "will be present during the event to ensure proper documentation.")

    # Event Details
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(50, 545, "Event Details")
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, 530, f"Event Name: {event_name}")
    pdf.drawString(50, 515, f"Date and Time: {event_date_time}")
    pdf.drawString(50, 500, f"Location: {location}")

    # Coverage Handling
    pdf.drawString(
        50, 460, "The coverage will be handled responsibly, and all photos/videos captured")
    pdf.drawString(50, 445, "will be shared post event upon request.")
    pdf.drawString(50, 415, "We appreciate your collaboration and")
    pdf.drawString(
        50, 400, "look forward to capturing memorable moments from your event.")

    # Further Instructions
    pdf.drawString(
        50, 360, "If you have any further instructions or requirements, please reach out to the")
    pdf.drawString(50, 345, "Pixel Club coordinators.")

    # Faculty Advisor
    pdf.drawString(50, 290, "Faculty Advisor")
    pdf.drawString(50, 275, f"({club_committee})")

    # Note
    pdf.drawString(
        50, 200, "Note: This form is system-generated. Please print it, get it signed by your Faculty")
    pdf.drawString(
        50, 185, "Advisor, and submit it to any Pixel Club member before the event.")
    pdf.drawString(50, 170, "No Pixel Club")
    pdf.drawString(50, 155, "signature is required.")

    pdf.save()
    buffer.seek(0)
    return buffer


# Send approval/rejection email with PDF attachment


def send_approval_email_with_pdf(user_name, recipient_email, event_details, action):
    """Send approval or rejection email with optional PDF attachment."""

    try:
        msg = MIMEMultipart()
        subject_action = "Approval" if action == "approve" else "Rejection"
        msg["Subject"] = f"Event Request {subject_action} Notification - {event_details['club']}"
        msg["From"] = SENDER_EMAIL
        msg["To"] = recipient_email
        print(recipient_email)

        if action == "reject":
            # Professional rejection message
            text = f"""
"""
            html = f"""<html>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
<p>Dear <strong>{user_name}</strong>,</p>
<p>We regret to inform you that, after careful review, your event request has been <strong>declined</strong>.</p>
<h3>Event Details:</h3>
<ul>
<li><strong>Organizing Club:</strong> {event_details['club']}</li>
<li><strong>Event Date:</strong> {event_details['request_date']}</li>
<li><strong>Event Time:</strong> {event_details['request_time']}</li>
<li><strong>Event Location:</strong> {event_details['location']}</li>
</ul>
<p>Unfortunately, due to scheduling constraints and limited resources, we are unable to accommodate your request at this time.</p>
<p>We appreciate your interest in collaborating with Pixel Club and encourage you to submit future requests.</p>
    <p><strong>Sincerely,</strong><br>Team Pixel Club</p>
    </body>
</html>"""
        else:
            # Professional approval message
            text = f"""
<p>Dear <strong>{user_name}</strong>,</p>
<p>Your event request has been <strong>approved</strong>. Please find the official approval letter attached.</p>
<h3>Event Details:</h3>
<ul>
<li><strong>Organizing Club:</strong> {event_details['club']}</li>
<li><strong>Event Date:</strong> {event_details['request_date']}</li>
<li><strong>Event Time:</strong> {event_details['request_time']}</li>
<li><strong>Event Location:</strong> {event_details['location']}</li>
</ul>
<p>Please ensure you carry a printed copy of this letter during your event.</p>
<p>If you have any questions or need further assistance, feel free to contact us.</p>
<p><strong>Best regards,</strong><br>Team Pixel Club</p>
</body>
</html>"""

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html, "html"))

        if action == "approve":
            # Generate PDF with individual arguments
            pdf_buffer = generate_approval_pdf(
                applicant_name=user_name,
                club_committee=event_details["club"],
                contact_no=event_details.get("contact_no", "N/A"),
                event_name=event_details.get("event_name", "N/A"),
                event_date_time=f"{event_details['request_date']} {event_details['request_time']}",
                location=event_details["location"]
            )
            pdf_data = pdf_buffer.read()
            pdf_part = MIMEApplication(pdf_data, _subtype="pdf")
            pdf_part.add_header(
                "Content-Disposition",
                "attachment",
                filename="Pixel_Club_Approval_Letter.pdf"
            )
            msg.attach(pdf_part)

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        return True, "Email sent successfully."

    except smtplib.SMTPAuthenticationError:
        return False, "Authentication with the email server failed. Please check credentials."
    except smtplib.SMTPException as e:
        return False, f"SMTP error occurred: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


# --- NEW: Unified Handle Request Action Route ---
@app.route("/admin/request/<int:request_id>/<string:action>/<string:role_type>", methods=["POST"])
@admin_required
def handle_request_action(request_id, action, role_type):
    if not session.get("admin_logged_in"):
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    username = session.get("admin_username")
    # 'super_admin', 'co_admin', or 'faculty_advisor'
    admin_role = session.get("admin_role")
    role_type = role_type.lower().strip()
    current_time = datetime.now()

    db_conn = None  # Initialize db_conn and cursor to None
    cursor = None

    # --- START OF THE FIX ---
    # Map the 'action' from the URL to the exact ENUM values required by the database
    db_action_value = None
    if action == "approve":
        db_action_value = "approved"
    elif action == "reject":
        db_action_value = "rejected"
    else:
        # This case should ideally not happen if the frontend sends valid actions
        return jsonify({"status": "error", "message": "Invalid action provided for database update."}), 400
    # --- END OF THE FIX ---

    try:
        db_conn = get_db_connection()
        cursor = db_conn.cursor(dictionary=True)

        # Fetch current request details
        cursor.execute(
            "SELECT * FROM permission_requests WHERE id = %s", (request_id,))
        request_details = cursor.fetchone()

        if not request_details:
            return jsonify({"status": "error", "message": "Request not found!"}), 404

        # Determine which role's columns to update based on role_type
        update_col_status = ""
        update_col_by = ""
        update_col_time = ""
        allowed = False
        # Flag to indicate if overall status needs re-evaluation
        overall_status_change = False

        if role_type == "pixel_member":
            if admin_role == "co_admin":  # Pixel Member is 'co_admin'
                update_col_status = "pixel_member_approval_status"
                update_col_by = "pixel_member_approval_by"
                update_col_time = "pixel_member_approval_time"
                allowed = True
                if action == "reject":  # Pixel Members cannot reject
                    return jsonify({"status": "error", "message": "Pixel Members cannot reject requests."}), 403
                overall_status_change = True
            else:
                return jsonify({"status": "error", "message": "Access denied for Pixel Member action."}), 403
        elif role_type == "pixel_head":
            if admin_role == "super_admin":  # Pixel Head is 'super_admin'
                update_col_status = "pixel_head_approval_status"
                update_col_by = "pixel_head_approval_by"
                update_col_time = "pixel_head_approval_time"
                allowed = True
                overall_status_change = True
            else:
                return jsonify({"status": "error", "message": "Access denied for Pixel Head action."}), 403
        elif role_type == "faculty_advisor":
            if admin_role == "faculty_advisor":  # Faculty Advisor is 'faculty_advisor' role
                update_col_status = "faculty_advisor_approval_status"
                update_col_by = "faculty_advisor_approval_by"
                update_col_time = "faculty_advisor_approval_time"
                allowed = True
                overall_status_change = True
            else:
                return jsonify({"status": "error", "message": "Access denied for Faculty Advisor action."}), 403
        else:
            return jsonify({"status": "error", "message": "Invalid role type provided."}), 400

        if not allowed:
            return jsonify({"status": "error", "message": "You do not have permission for this action."}), 403

        # Execute the update for the specific role
        update_query = f"""
            UPDATE permission_requests
            SET {update_col_status} = %s,
                {update_col_by} = %s,
                {update_col_time} = %s
            WHERE id = %s
        """
        # DEBUG: Now printing the value that will actually be sent to the DB
        print(
            f"DEBUG: Attempting to update column '{update_col_status}' with value: '{db_action_value}' for request ID: {request_id}")
        # --- IMPORTANT: Use db_action_value here instead of action ---
        cursor.execute(update_query, (db_action_value,
                       username, current_time, request_id))
        db_conn.commit()

        # Re-fetch the *updated* request details to check overall status
        cursor.execute(
            "SELECT * FROM permission_requests WHERE id = %s", (request_id,))
        updated_request_details = cursor.fetchone()

        # Overall Status Check and Email Trigger
        # Default to current status
        new_overall_status = updated_request_details['status']

        if overall_status_change:  # Only re-evaluate if one of the specific approvals changed
            member_status = updated_request_details['pixel_member_approval_status']
            head_status = updated_request_details['pixel_head_approval_status']
            advisor_status = updated_request_details['faculty_advisor_approval_status']

            if db_action_value == "rejected":  # Check against db_action_value
                # If any role rejects, the overall status becomes 'rejected'
                new_overall_status = "rejected"
            elif member_status == 'approved' and head_status == 'approved' and advisor_status == 'approved':
                new_overall_status = "approved"
            else:
                # Keep as pending if not all approved and not rejected
                new_overall_status = "pending"

            # Only update if the overall status has actually changed
            if new_overall_status != updated_request_details['status']:
                cursor.execute(
                    """
                    UPDATE permission_requests
                    SET status = %s,
                        decision_date = %s,
                        decision_by = %s
                    WHERE id = %s
                    """,
                    (new_overall_status, current_time, username, request_id)
                )
                db_conn.commit()

        # Determine flash message and email sending
        message_status = "success"
        message_text = ""
        send_email_now = False
        email_approval_type = None

        if new_overall_status == "approved" and updated_request_details['email_notification_status'] != 'Sent':
            message_text = "Request fully approved and email is being sent!"
            send_email_now = True
            email_approval_type = "approve"
        elif new_overall_status == "rejected" and updated_request_details['email_notification_status'] != 'Sent':
            message_text = "Request rejected and email is being sent!"
            send_email_now = True
            email_approval_type = "reject"
        elif db_action_value == "approved":  # Individual approval, not yet overall approved
            message_status = "info"
            message_text = f"{role_type.replace('_', ' ').title()} approval recorded. Waiting for other approvals."
        elif db_action_value == "rejected":  # Individual rejection, overall status already set to rejected
            message_status = "warning"
            message_text = f"{role_type.replace('_', ' ').title()} rejected request."
        else:
            message_status = "info"
            # Fallback for other actions/statuses
            message_text = f"Action {db_action_value} recorded."

        # Send email if marked for sending
        if send_email_now:
            event_details = {
                "club": updated_request_details['club'],
                "request_date": updated_request_details['request_date'],
                "request_time": updated_request_details['request_time'],
                "location": updated_request_details['location'],
                "contact_no": updated_request_details.get('contact_no', 'N/A'),
                "event_name": updated_request_details.get('event_name', 'N/A')
            }
            recipient_email = updated_request_details.get('email_id')
            if not recipient_email:
                print(
                    f"[EMAIL] Will send to {recipient_email} for request #{request_id}")
                return jsonify({"status": "error", "message": "Recipient email not found."}), 400

            email_success, email_message = send_approval_email_with_pdf(
                updated_request_details['user_name'], recipient_email, event_details, email_approval_type
            )

            if not email_success:
                message_status = "warning"
                message_text = f"{message_text} However, email failed: {email_message}"
                # Optionally, update email_notification_status to 'Failed' or keep 'Pending'
                cursor.execute(
                    "UPDATE permission_requests SET email_notification_status = 'Pending' WHERE id = %s",
                    (request_id,)
                )
                db_conn.commit()
            else:
                # Update email_notification_status to 'Sent' if email was successfully sent
                cursor.execute(
                    "UPDATE permission_requests SET email_notification_status = 'Sent' WHERE id = %s",
                    (request_id,)
                )
                db_conn.commit()

        return jsonify({
            "status": message_status,
            "message": message_text,
            "new_overall_status": new_overall_status,
            "was_email_sent": send_email_now
        })

    except mysql.connector.Error as err:  # Catch specific MySQL errors for more detail
        db_conn.rollback()
        # Print full MySQL error details
        print(
            f"MySQL Error (errno: {err.errno}, sqlstate: {err.sqlstate}): {err.msg}")
        return jsonify({"status": "error", "message": f"Database error: {err.msg}"}), 500
    except Exception as e:  # Catch any other general exceptions
        db_conn.rollback()
        print(f"General Server Error: {str(e)}")  # Print general error
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500
    finally:
        if cursor:
            cursor.close()
        if db_conn:
            db_conn.close()


def user_login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("user_login_page"))
        return f(*args, **kwargs)

    return wrap


# ✅ Check if email already exists
def email_already_exists(email):
    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM pixel_users WHERE email = %s", (email,))
    result = cursor.fetchone()
    cursor.close()
    db.close()
    return result is not None


# ✅ Send OTP
@app.route("/send_otp", methods=["POST"])
def send_otp():
    name = request.form["username"]
    email = request.form["email"]

    if not email.endswith("@gcekarad.ac.in"):
        return "Only @gcekarad.ac.in emails allowed", 400

    if email_already_exists(email):
        return "Account already exists with this email.", 409

    otp = str(random.randint(100000, 999999))
    session["otp"] = otp
    session["temp_user"] = {"username": name, "email": email}

    message = f"Subject: PIXEL CLUB OTP Verification\n\nHello {name},\nYour OTP is: {otp}"

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, message)
        server.quit()
    except Exception as e:
        return f"Error sending email: {e}", 500

    return "OTP sent successfully"


# ✅ Verify OTP and register user
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    otp_input = request.form.get("otp")
    password = request.form.get("password")
    confirm_password = request.form.get("confirm_password")

    print("[DEBUG] OTP from form:", otp_input)
    print("[DEBUG] OTP in session:", session.get("otp"))
    print("[DEBUG] Session Temp User:", session.get("temp_user"))

    if not otp_input or not password or not confirm_password:
        return "Missing OTP or passwords", 400

    if password != confirm_password:
        return "Passwords do not match", 400

    if "otp" not in session or "temp_user" not in session:
        return "Session expired. Please restart registration.", 400

    if otp_input != session["otp"]:
        return "Incorrect OTP", 400

    username = session["temp_user"]["username"]
    email = session["temp_user"]["email"]

    hashed_password = bcrypt.hashpw(password.encode(
        "utf-8"), bcrypt.gensalt()).decode("utf-8")

    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute(
            "INSERT INTO pixel_users (name, email, password, is_verified) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, True),
        )
        db.commit()
    except mysql.connector.Error as err:
        db.rollback()
        cursor.close()
        db.close()
        return f"Database error: {err}", 500

    cursor.close()
    db.close()

    session.pop("otp", None)
    session.pop("temp_user", None)

    return "Success"


def send_email(to_email, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = to_email

    try:
        # Use SMTP_SSL for port 465
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            # For SMTP_SSL, you don't typically call server.starttls()
            # The connection is secured immediately upon creation
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        return True
    except smtplib.SMTPAuthenticationError:
        print("Error: Authentication failed. Check your SENDER_EMAIL and SENDER_PASSWORD (App Password for Gmail with 2FA).")
        return False
    except smtplib.SMTPConnectError as e:
        print(
            f"Error: Could not connect to SMTP server. Check server address, port, and network/firewall. Details: {e}")
        return False
    except smtplib.SMTPException as e:
        print(f"Error sending email: SMTP error occurred. Details: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred while sending email: {e}")
        return False


# --- Your existing user_login_page route ---
@app.route("/user_login", methods=["GET", "POST"])
def user_login_page():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute(
            "SELECT id,name, email, password FROM pixel_users WHERE email = %s AND is_verified = TRUE", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if user:
            stored_hashed_password = user[3]
            # Ensure both are bytes before checking
            if bcrypt.checkpw(password.encode("utf-8"), stored_hashed_password.encode("utf-8")):
                session["user_id"] = user[0]
                session["email"] = user[2]
                session["user_logged_in"] = True
                flash("Login successful!", "success")
                # Or your desired post-login page
                return redirect(url_for("imgkit_gallery"))
            else:
                flash("Incorrect password.", "error")
        else:
            flash("Invalid email or account not verified.", "error")

        return redirect(url_for("user_login_page"))

    return render_template("login_page.html")

# --- New Route for Forgot Password Request (Send OTP) ---


@app.route("/forgot_password_request_otp", methods=["POST"])
def forgot_password_request_otp():
    email = request.form.get("email")
    if not email:
        return "Email is required.", 400

    # Basic email validation (you can enhance this)
    if not email.endswith('@gcekarad.ac.in'):
        return "Only @gcekarad.ac.in emails are allowed for password reset.", 403

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM pixel_users WHERE email = %s", (email,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        db.close()
        return "No account found with that email.", 404

    user_id = user[0]
    otp = str(secrets.randbelow(900000) + 100000)  # Generate 6-digit OTP
    otp_created_at = datetime.now()

    try:
        # Store OTP and timestamp in the database
        cursor.execute("UPDATE pixel_users SET otp_secret = %s, otp_created_at = %s WHERE id = %s",
                       (otp, otp_created_at, user_id))
        db.commit()

        subject = "PIXEL CLUB Password Reset OTP"
        body = f"Hello,\n\nYour OTP for password reset is: {otp}\n\nThis OTP is valid for 10 minutes.\n\nIf you did not request a password reset, please ignore this email.\n\nRegards,\nPIXEL CLUB Team"
        if send_email(email, subject, body):
            return "OTP sent to your email."
        else:
            db.rollback()  # Rollback if email sending fails
            return "Failed to send OTP email. Please try again later.", 500
    except Exception as e:
        db.rollback()
        print(f"Database error during OTP storage: {e}")
        return "An internal error occurred.", 500
    finally:
        cursor.close()
        db.close()


# --- New Route for Reset Password Confirmation ---
@app.route("/reset_password_confirm", methods=["POST"])
def reset_password_confirm():
    email = request.form.get("email")
    otp = request.form.get("otp")
    new_password = request.form.get("new_password")
    print(
        f"Received for reset: Email={email}, OTP={otp}, New Password Length={len(new_password) if new_password else 'N/A'}")

    if not all([email, otp, new_password]):
        return "All fields are required.", 400

    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute(
        "SELECT id, otp_secret, otp_created_at FROM pixel_users WHERE email = %s", (email,))
    user_data = cursor.fetchone()

    if not user_data:
        cursor.close()
        db.close()
        return "Invalid email or OTP.", 400

    id, stored_otp, otp_timestamp = user_data

    # Check if OTP matches and is not expired (e.g., 10 minutes validity)
    # 600 seconds = 10 minutes
    if stored_otp == otp and otp_timestamp and (datetime.now() - otp_timestamp).total_seconds() < 600:
        # Hash the new password
        hashed_new_password = bcrypt.hashpw(new_password.encode(
            "utf-8"), bcrypt.gensalt()).decode("utf-8")

        try:
            # Update password and clear OTP fields
            cursor.execute("UPDATE pixel_users SET password = %s, otp_secret = NULL, otp_created_at = NULL WHERE id = %s",
                           (hashed_new_password, id))
            db.commit()
            cursor.close()
            return "Password reset successfully! You can now log in with your new password."

        except Exception as e:
            db.rollback()
            print(f"Database error during password update: {e}")
            return "An error occurred while updating your password.", 500
    else:
        return "Invalid or expired OTP.", 400


# ✅ Logout
@app.route("/user_logout", methods=["GET", "POST"])
@user_login_required
def user_logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("index"))


@app.route("/permissions")
@user_login_required
def permissions():
    if "user_id" in session and "email" in session:
        user_id = session["user_id"]
        user_email = session["email"]

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute(
            "SELECT name FROM pixel_users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        db.close()

        # Fallback if name not found, though it should be
        user_name = user_data[0] if user_data else "Guest"

        return render_template("permissions.html", user_name=user_name, user_email=user_email)
    else:
        # This case should ideally be caught by @user_login_required,
        # but it's good to have a fallback.
        flash("Please log in to access the permission form.")
        return redirect(url_for("user_login_page"))


@app.route("/requests")
def requests():
    requests = get_requests_from_database()
    return render_template("requests.html", requests=requests, admin_role=session.get('admin_role', 'guest'))


@app.route("/submit_permission", methods=["POST"])
def submit_permission():
    name = request.form.get("name")
    clg_mail = request.form.get("clg_mail")
    club = request.form.get("club")
    date = request.form.get("date")
    time = request.form.get("time")
    location = request.form.get("location")
    contact_no = request.form.get("contact_no")
    email_id = request.form.get("contact_mail")

    # Validation
    if not all([name, clg_mail, club, date, time, location, contact_no, email_id]):
        flash("All fields are required!", "danger")
        return redirect(url_for("permissions"))

    save_permission_request(name, clg_mail, club, date,
                            time, location, contact_no, email_id)
    flash("Permission request submitted successfully!", "success")
    return redirect(url_for("permissions"))


def get_requests_from_database():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM request_history")
    requests = cursor.fetchall()
    cursor.close()
    conn.close()
    return requests

# def get_requests_from_database():
#     db = None
#     cursor = None
#     requests_list = []
#     try:
#         db = get_db_connection()
#         cursor = db.cursor(dictionary=True,buffered=True) # Use dictionary=True to fetch rows as dictionaries
#         # Select all columns from your requests table
#         cursor.execute("""
#             SELECT
#                 id, user_name, club, request_date, request_time, location, contact_no, status,
#                 created_at, email_id, decision_date, decision_by, Accepted_by,
#                 pixel_member_approval_status, pixel_member_approval_by, pixel_member_approval_time,
#                 pixel_head_approval_status, pixel_head_approval_by, pixel_head_approval_time,
#                 Clg_Mail, faculty_advisor_approval_status, faculty_advisor_approval_by, faculty_advisor_approval_time,
#                 email_notification_status
#             FROM permission_requests
#             ORDER BY created_at DESC; -- Order by creation date for latest requests first
#         """)
#         requests_list = cursor.fetchall()
#     except mysql.connector.Error as err:
#         print(f"Error fetching requests: {err}")
#         # In a real application, you might want to log this error and show a user-friendly message
#     finally:
#         if cursor:
#             cursor.close()
#         if db:
#             db.close()
#     return requests_list


def save_permission_request(name, clg_mail, club, date, time, location, contact_no, contact_mail):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
        INSERT INTO permission_requests (user_name,clg_mail, club, request_date, request_time, location, contact_no, email_id, status, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (name, clg_mail, club, date, time, location,
                  contact_no, contact_mail, "pending", datetime.now())

        print(name, club, date, time, location, contact_no, contact_mail)

        cursor.execute(query, values)
        conn.commit()
    except mysql.connector.Error as err:
        print("❌ DATABASE ERROR:", err)
        flash(f"Database Error: {err}", "danger")
        return

    finally:
        cursor.close()
        conn.close()


@app.route("/team")
def team():
    
    # Fetch team members
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT id, name, role, photo
        FROM login
        WHERE role IN ('super_admin', 'co_admin', 'faculty_advisor')
        ORDER BY role ASC
    """)
    team_members = cursor.fetchall()
    cursor.close()
    db.close()
    return render_template("team.html",team_members=team_members)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# # Gallery Management Routes
# @app.route("/admin/gallery")
# @admin_required
# def admin_gallery():
#     if not session.get("admin_logged_in"):
#         flash("Please log in first.", "warning")
#         return redirect(url_for("admin_login"))

#     db = get_db_connection()
#     cursor = db.cursor(dictionary=True)
#     cursor.execute("SELECT * FROM gallery_items ORDER BY event_date DESC")
#     gallery_items = cursor.fetchall()
#     cursor.close()
#     db.close()

#     return render_template("admin_gallery.html", gallery_items=gallery_items)


# @app.route("/admin/gallery/add", methods=["POST"])
# def add_gallery_item():
#     if not session.get("admin_logged_in"):
#         return jsonify({"status": "error", "message": "Unauthorized access!"}), 401

#     try:
#         os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

#         # Get form data
#         title = request.form.get("title")
#         event_date = request.form.get("event_date")
#         google_photos_link = request.form.get("google_photos_link", "")
#         file = request.files.get("cover_image")

#         # Validate inputs
#         if not all([title, event_date, file]):
#             return jsonify({"status": "error", "message": "Title, date and image are required!"}), 400

#         if file.filename == "":
#             return jsonify({"status": "error", "message": "No file selected!"}), 400

#         if not allowed_file(file.filename):
#             return jsonify({"status": "error", "message": "Invalid file type!"}), 400

#         # Process file upload
#         filename = secure_filename(file.filename)
#         save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
#         file.save(save_path)

#         # Database operation
#         db = get_db_connection()
#         cursor = db.cursor()
#         cursor.execute(
#             "INSERT INTO gallery_items (title, event_date, google_photos_link, cover_image_path) VALUES (%s, %s, %s, %s)",
#             (title, event_date, google_photos_link, filename),
#         )
#         db.commit()

#         return jsonify({"status": "success", "message": "Gallery item added successfully!", "filename": filename}), 200

#     except Exception as e:
#         print(f"Error in add_gallery_item: {str(e)}")
#         return jsonify({"status": "error", "message": f"Error adding gallery item: {str(e)}"}), 500
#     finally:
#         if "cursor" in locals():
#             cursor.close()
#         if "db" in locals():
#             db.close()


# # Temporary route to fix existing data
# @app.route("/fix-image-paths")
# def fix_image_paths():
#     if not session.get("admin_logged_in"):
#         return "Unauthorized", 401

#     db = get_db_connection()
#     cursor = db.cursor()

#     try:
#         # Get all items
#         cursor.execute("SELECT id, cover_image_path FROM gallery_items WHERE cover_image_path IS NOT NULL")
#         items = cursor.fetchall()

#         for item_id, path in items:
#             if path:
#                 # Clean up the path
#                 clean_path = path.replace("\\", "/")
#                 clean_path = clean_path.split("/")[-1]

#                 # Update the database
#                 cursor.execute("UPDATE gallery_items SET cover_image_path = %s WHERE id = %s", (clean_path, item_id))

#         db.commit()
#         return "Image paths fixed successfully"
#     except Exception as e:
#         db.rollback()
#         return f"Error: {str(e)}", 500
#     finally:
#         cursor.close()
#         db.close()


# @app.route("/admin/gallery/delete/<int:item_id>", methods=["POST"])
# @admin_required
# def delete_gallery_item(item_id):
#     if not session.get("admin_logged_in"):
#         return jsonify({"status": "error", "message": "Unauthorized access!"}), 401

#     db = get_db_connection()
#     cursor = db.cursor(dictionary=True)

#     try:
#         # Get the file path
#         cursor.execute("SELECT cover_image_path FROM gallery_items WHERE id = %s", (item_id,))
#         item = cursor.fetchone()

#         if item:
#             try:
#                 # Delete the file from filesystem
#                 if item["cover_image_path"]:
#                     file_path = os.path.join(app.config["UPLOAD_FOLDER"], item["cover_image_path"])
#                     if os.path.exists(file_path):
#                         os.remove(file_path)
#             except Exception as e:
#                 print(f"Error deleting file: {e}")

#             # Delete from database
#             cursor.execute("DELETE FROM gallery_items WHERE id = %s", (item_id,))
#             db.commit()

#             return jsonify({"status": "success", "message": "Gallery item deleted successfully!", "item_id": item_id})
#         else:
#             return jsonify({"status": "error", "message": "Gallery item not found!"}), 404

#     except Exception as e:
#         db.rollback()
#         return jsonify({"status": "error", "message": str(e)}), 500
#     finally:
#         cursor.close()
#         db.close()


# @app.route("/api/gallery")
# def api_gallery():
#     db = get_db_connection()
#     cursor = db.cursor(dictionary=True)
#     cursor.execute(
#         """
#         SELECT id, title, event_date, google_photos_link,
#                cover_image_path
#         FROM gallery_items
#         WHERE cover_image_path IS NOT NULL
#         ORDER BY event_date DESC
#     """
#     )
#     items = cursor.fetchall()
#     cursor.close()
#     db.close()

#     # Clean up the paths
#     for item in items:
#         if item["cover_image_path"]:
#             item["cover_image_path"] = item["cover_image_path"].replace("\\", "/")
#             item["cover_image_path"] = item["cover_image_path"].replace("static/uploads/gallery/", "")
#             item["cover_image_path"] = item["cover_image_path"].replace("uploads/gallery/", "")

#     return jsonify(items)

@app.route("/admin/request_history")
@admin_required
def request_history():
    if not session.get("admin_logged_in"):
        flash("Please log in first.", "warning")
        return redirect(url_for("admin_login"))

    status_filter = request.args.get("status", "all")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")

    # Pagination parameters
    page = request.args.get("page", 1, type=int)
    per_page = 10  # Number of requests per page, you can adjust this

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # First, get the total count of requests for pagination
    count_query = "SELECT COUNT(*) AS total FROM request_history WHERE 1=1"
    count_params = []

    if status_filter != "all":
        count_query += " AND status = %s"
        count_params.append(status_filter)

    if date_from:
        count_query += " AND deleted_at >= %s"
        count_params.append(date_from)

    if date_to:
        count_query += " AND deleted_at <= %s"
        count_params.append(date_to)

    cursor.execute(count_query, count_params)
    total_requests = cursor.fetchone()["total"]
    total_pages = math.ceil(total_requests / per_page)

    # Now, get the paginated requests
    query = "SELECT * FROM request_history WHERE 1=1"
    params = []

    if status_filter != "all":
        query += " AND status = %s"
        params.append(status_filter)

    if date_from:
        query += " AND deleted_at >= %s"
        params.append(date_from)

    if date_to:
        query += " AND deleted_at <= %s"
        params.append(date_to)

    query += " ORDER BY deleted_at DESC LIMIT %s OFFSET %s"
    params.append(per_page)
    params.append((page - 1) * per_page)

    cursor.execute(query, params)
    requests = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        "request_history.html",
        requests=requests,
        status_filter=status_filter,
        date_from=date_from,
        date_to=date_to,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        total_requests=total_requests
    )


@app.route("/download_request_history")
@admin_required
def download_request_history():
    """Generate a PDF file of filtered request history and return it as a download."""
    status_filter = request.args.get("status", "all")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")

    db = get_db_connection()  # Assuming this connects to your database
    cursor = db.cursor(dictionary=True)

    query = "SELECT * FROM request_history where 1=1"
    params = []

    if status_filter != "all":
        query += " AND status = %s"
        params.append(status_filter)

    if date_from:
        query += " AND request_date >= %s"
        params.append(date_from)

    if date_to:
        query += " AND request_date <= %s"
        params.append(date_to)

        query += " ORDER BY request_date DESC"

        print("Final Query:", query)
        print("Parameters:", params)

    cursor.execute(query, tuple(params))
    requests = cursor.fetchall()

    cursor.close()
    db.close()

    # Create PDF in memory
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.setTitle("Request History Report")

    # **Header**
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(200, 800, "Event Covered Request History Report")

    pdf.setFont("Helvetica", 10)
    pdf.drawString(
        50, 780, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    pdf.line(50, 775, 550, 775)

    # **Table Headers**
    pdf.setFont("Helvetica-Bold", 10)
    headers = ["ID", "Name", "Club", "Request Date",
               "Decision Date", "Contact No", "Status"]
    x_positions = [50, 90, 180, 270, 350, 430, 500]

    for i, header in enumerate(headers):
        pdf.drawString(x_positions[i], 750, header)

    pdf.line(50, 745, 550, 745)

    # **Table Content**
    pdf.setFont("Helvetica", 9)
    y_position = 730
    for req in requests:
        pdf.drawString(50, y_position, str(req["id"]))
        pdf.drawString(90, y_position, req["user_name"])
        pdf.drawString(180, y_position, req["club"])
        pdf.drawString(270, y_position, str(req["request_date"]))
        pdf.drawString(350, y_position, str(req["location"] or "N/A"))
        pdf.drawString(430, y_position, req["contact_no"] or "N/A")
        pdf.drawString(500, y_position, req["status"].capitalize())

        y_position -= 20
        if y_position < 50:
            pdf.showPage()
            y_position = 750

    # **Footer**
    pdf.line(50, 30, 550, 30)
    pdf.setFont("Helvetica-Oblique", 9)
    pdf.drawString(230, 20, "©Pixel GCEK All rights reserved")

    pdf.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name=f"Event_Covered_Request_History_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", mimetype="application/pdf")


@app.route("/event_calendar")
def event_calendar():
    try:
        # Get current year and month with error handling
        now = datetime.now()
        try:
            year = int(request.args.get("year", now.year))
            month = int(request.args.get("month", now.month))
            # Validate month range
            month = max(1, min(12, month))
        except ValueError:
            year = now.year
            month = now.month

        # Calculate month boundaries
        first_day = datetime(year, month, 1)
        if month == 12:
            last_day = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            last_day = datetime(year, month + 1, 1) - timedelta(days=1)

        # Database operations with error handling
        try:
            db = get_db_connection()
            cursor = db.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT club AS event_name, 
                       request_date AS event_date, 
                       request_time AS event_time, 
                       location
                FROM permission_requests 
                WHERE status = 'approved' 
                  AND request_date BETWEEN %s AND %s
                ORDER BY request_date, request_time
            """,
                (first_day.date(), last_day.date()),
            )

            events = cursor.fetchall()
            events_by_date = {}
            for event in events:
                date_str = event["event_date"].strftime("%Y-%m-%d")
                if date_str not in events_by_date:
                    events_by_date[date_str] = []
                events_by_date[date_str].append(event)

        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "danger")
            events_by_date = {}
        finally:
            if "cursor" in locals():
                cursor.close()
            if "db" in locals():
                db.close()

        # Calculate navigation dates
        prev_month = month - 1 if month > 1 else 12
        prev_year = year if month > 1 else year - 1
        next_month = month + 1 if month < 12 else 1
        next_year = year if month < 12 else year + 1

        return render_template(
            "event_calendar.html",
            year=year,
            month=month,
            month_name=first_day.strftime("%B"),
            events_by_date=events_by_date,
            first_day_weekday=first_day.weekday(),
            days_in_month=last_day.day,
            prev_month=prev_month,
            prev_year=prev_year,
            next_month=next_month,
            next_year=next_year,
            today=now.date(),
        )

    except Exception as e:
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for("index"))


#  Image Kit Implimentation


UPLOAD_FOLDER = 'static/originals'
COMPRESSED_FOLDER = 'static/compressed'
GALLERY_JSON = 'gallery.json'
STAGED_JSON = 'staged_album.json'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(COMPRESSED_FOLDER, exist_ok=True)

imagekit = ImageKit(
    public_key='public_zjFRE3HNcxXtKVnhVb7IH/sI3fI=',
    private_key='private_TeIw1EMxZQBKpNZr+3+G00DcXKo=',
    url_endpoint='https://ik.imagekit.io/gcekpixelclub'
)


def compress_and_upload(filename, folder_name):
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    output_filename = os.path.splitext(filename)[0] + ".webp"
    output_path = os.path.join(COMPRESSED_FOLDER, output_filename)

    with Image.open(input_path) as img:
        img = img.convert("RGB")
        if img.width > 1200:
            ratio = 1200 / img.width
            img = img.resize((1200, int(img.height * ratio)), Image.LANCZOS)
        for q in range(75, 20, -5):
            img.save(output_path, "webp", quality=q)
            if os.path.getsize(output_path) < 5 * 1024 * 1024:
                break

    with open(output_path, 'rb') as file_data:
        options = UploadFileRequestOptions(
            folder="/" + folder_name,
            use_unique_file_name=False,
            overwrite_file=True
        )
        imagekit.upload_file(
            file=file_data,
            file_name=output_filename,
            options=options
        )

    return output_filename


@app.route('/imgkit_admin_gallery', methods=['GET', 'POST'])
@pixel_head_or_member_required
@admin_required
def imgkit_admin_gallery():
    if request.method == 'POST':
        title = request.form['title']
        date = request.form['date']
        description = request.form['description']
        folder = request.form['folder']
        drive_folder_input = request.form['drive_links']
        published = 'published' in request.form

        drive_folder_id = extract_folder_id(drive_folder_input)
        try:
            images = fetch_images_from_drive(drive_folder_id, UPLOAD_FOLDER)
        except Exception as e:
            flash(f"Failed to fetch images from Drive: {e}", 'error')
            return redirect(url_for('imgkit_admin_gallery'))

        uploaded_webps = []
        drive_links = []

        for img in images:
            fname = img['name']
            try:
                webp_file = compress_and_upload(fname, folder)
                uploaded_webps.append(webp_file)
                drive_links.append(img['download_link'])
            except Exception as e:
                flash(f"Error processing {fname}: {e}", 'error')

        staged_album = {
            "title": title,
            "date": date,
            "description": description,
            "folder": folder,
            "preview": f"https://ik.imagekit.io/gcekpixelclub/{folder}/",
            "images": uploaded_webps,
            "downloads": drive_links,
            "published": published
        }

        with open(STAGED_JSON, 'w') as f:
            json.dump(staged_album, f, indent=2)

        return redirect(url_for('admin_review_albums'))

    try:
        with open(GALLERY_JSON, 'r') as f:
            albums = json.load(f)
    except Exception:
        albums = []

    indexed_albums = []
    for idx, album in enumerate(albums):
        album_copy = album.copy()
        album_copy['__index'] = idx
        indexed_albums.append(album_copy)

    published_albums = [a for a in indexed_albums if a.get("published")]
    draft_albums = [a for a in indexed_albums if not a.get("published")]

    return render_template('imgkit_admin_gallery.html',
                           published_albums=published_albums,
                           draft_albums=draft_albums)


@app.route("/admin_review_albums", methods=['GET', 'POST'])
@admin_required
def admin_review_albums():
    if not os.path.exists(STAGED_JSON):
        flash("No album to review", "error")
        return redirect(url_for('imgkit_admin_gallery'))

    with open(STAGED_JSON, 'r') as f:
        album = json.load(f)

    image_download_pairs = list(zip(album['images'], album['downloads']))

    if request.method == 'POST':
        thumbnail = request.form.get('thumbnail')
        images_to_keep = request.form.getlist('keep')

        final_images = [img for img in album['images']
                        if img in images_to_keep]
        final_downloads = [d for img, d in zip(
            album['images'], album['downloads']) if img in images_to_keep]

        album['images'] = final_images
        album['downloads'] = final_downloads
        album['thumbnail'] = thumbnail

        if os.path.exists(GALLERY_JSON):
            with open(GALLERY_JSON, 'r') as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = []
        else:
            data = []

        data.append(album)

        with open(GALLERY_JSON, 'w') as f:
            json.dump(data, f, indent=2)

        os.remove(STAGED_JSON)
        flash("Album published successfully!", "success")
        return redirect(url_for('imgkit_admin_gallery'))

    return render_template("imgkit_admin_review.html", album=album, image_download_pairs=image_download_pairs)


@app.route("/imgkit_gallery")
@user_login_required
def imgkit_gallery():
    # Load all albums
    with open("gallery.json", "r") as f:
        albums = json.load(f)

    # Only published albums
    published = [a for a in albums if a.get("published")]

    # Attach preview thumbnail if missing (already handled in the provided JSON, but good practice)
    for album in published:
        images = album.get("images", [])
        downloads = album.get("downloads", [])
        # This is not strictly needed for gallery view but keeping it for consistency if needed later
        album["image_download_pairs"] = list(zip(images, downloads))

    return render_template("imgkit_gallery.html", albums=published)


@app.route("/imgkit_gallery/<int:index>")
@user_login_required
def gallery_album(index):
    # Load all albums
    with open("gallery.json", "r") as f:
        albums = json.load(f)

    # Get the specific album by index
    # Add error handling for invalid index if necessary in a production app
    if 0 <= index < len(albums):
        album = albums[index]
        # Combine images and downloads for easy iteration in the template
        album["image_download_pairs"] = list(
            zip(album["images"], album["downloads"]))
        return render_template("imgkit_album_detail.html", album=album, index=index)
    else:
        # Redirect to gallery or show a 404 error
        return redirect(url_for('imgkit_gallery'))


@app.route('/toggle/<int:index>', methods=['POST'])
@admin_required
def toggle_publish(index):
    try:
        with open(GALLERY_JSON, 'r') as f:
            albums = json.load(f)

        albums[index]['published'] = not albums[index].get('published', False)

        with open(GALLERY_JSON, 'w') as f:
            json.dump(albums, f, indent=2)

        flash("Album status updated!", "success")
    except Exception as e:
        flash(f"Error toggling album: {e}", "error")

    return redirect(url_for('imgkit_admin_gallery'))


@app.route('/delete/<int:index>', methods=['POST'])
@admin_required
def delete_album(index):
    try:
        with open(GALLERY_JSON, 'r') as f:
            albums = json.load(f)

        if 0 <= index < len(albums):
            deleted = albums.pop(index)
            with open(GALLERY_JSON, 'w') as f:
                json.dump(albums, f, indent=2)
            flash(f"Deleted album: {deleted['title']}", "success")
        else:
            flash("Invalid album index", "error")
    except Exception as e:
        flash(f"Failed to delete album: {e}", "error")

    return redirect(url_for('imgkit_admin_gallery'))


# This is the Inventery Section


# ---------- Utility ----------
def has_approval(request_id, approver):
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT COUNT(*) AS count FROM equipment_approvals 
        WHERE request_id = %s AND approved_by = %s
    """, (request_id, approver))
    result = cursor.fetchone()
    cursor.close()
    return result['count'] > 0

# ---------- Routes ----------
# @app.route('/')
# def index():
#     return redirect(url_for('inventory'))


@app.route('/inventory')
@admin_required
@pixel_head_or_member_required
def inventory():
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM equipment")
    equipment = cursor.fetchall()
    cursor.close()
    return render_template('Equipment_inventory.html', equipment=equipment)


@app.route('/add_equipment', methods=['GET', 'POST'])
@admin_required
@pixel_head_or_member_required
def add_equipment():
    if request.method == 'POST':
        name = request.form['name']
        type_ = request.form['type']
        brand = request.form['brand_model']
        quantity = int(request.form['quantity'])
        notes = request.form['notes']
        available = quantity
        status = 'Available'
        image_url = ''

        db_conn = get_db_connection()
        cursor = db_conn.cursor(dictionary=True)
        cursor.execute("""
            INSERT INTO equipment (name, type, brand_model, quantity, available, status, notes, image_url)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (name, type_, brand, quantity, available, status, notes, image_url))
        db_conn.commit()
        cursor.close()
        return redirect(url_for('inventory'))

    return render_template('add_equipment.html')


@app.route('/delete_item/<int:del_id>', methods=['POST'])
@admin_required
@pixel_head_or_member_required
def delete_item(del_id):
    # No need for if request.method == 'GET': because the route is defined as POST
    # The del_id is already available from the URL path due to <int:del_id>

    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)
    cursor.execute("""
        DELETE FROM equipment where id = %s
    """, (del_id,))  # Use %s for parameter substitution and ensure it's a tuple
    print(
        # F-string for better message
        f"Item with ID {del_id} Removed Successfully")
    db_conn.commit()
    cursor.close()
    return redirect(url_for('inventory'))


@app.route('/issue', methods=['GET', 'POST'])
@admin_required
@pixel_head_or_member_required
def issue_equipment():
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)

    if request.method == 'POST':
        borrower_name = request.form['borrower_name']
        equipment_id = int(request.form['equipment_id'])
        return_date = request.form['return_date']
        remarks = request.form['remarks']
        issue_date = date.today()

        # Insert into equipment_log
        cursor.execute("""
            INSERT INTO equipment_log (equipment_id, borrower_name, issued_at, return_date, status)
            VALUES (%s, %s, %s, %s, %s)
        """, (equipment_id, borrower_name, issue_date, return_date, 'Issued'))

        # Decrease availability
        cursor.execute("""
            UPDATE equipment SET available = available - 1
            WHERE id = %s AND available > 0
        """, (equipment_id,))

        db_conn.commit()
        cursor.close()
        return redirect(url_for('inventory'))

    cursor.execute("SELECT * FROM equipment WHERE available > 0")
    equipment = cursor.fetchall()
    cursor.close()
    return render_template('Equipment_issue_form.html', equipment=equipment)


@app.route('/logs')
@admin_required
@pixel_head_or_member_required
def equipment_logs():
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)

    # --- Pagination Parameters ---
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of items per page
    offset = (page - 1) * per_page

    # --- Search Filter Parameters ---
    search_equipment = request.args.get('equipment_name', '').strip()
    search_borrower = request.args.get('borrower_name', '').strip()
    search_status = request.args.get('status', '').strip()

    # --- Build SQL Query ---
    # Base query for fetching logs with equipment name
    # Assuming 'equipment_requests' table has equipment_id, borrower_name, issued_at, return_date, status
    # And 'equipment' table has id, name
    query = """
        SELECT
            er.id,
            e.name AS equipment_name,
            er.borrower_name,
            er.issued_at,
            er.return_date,
            er.status
        FROM
            equipment_log AS er
        JOIN
            equipment AS e ON er.equipment_id = e.id
    """
    count_query = """
        SELECT COUNT(er.id)
        FROM equipment_log AS er
        JOIN equipment AS e ON er.equipment_id = e.id
    """

    conditions = []
    params = []

    if search_equipment:
        conditions.append("e.name LIKE %s")
        params.append(f"%{search_equipment}%")
    if search_borrower:
        conditions.append("er.borrower_name LIKE %s")
        params.append(f"%{search_borrower}%")
    if search_status:
        conditions.append("er.status = %s")  # Assuming exact match for status
        params.append(search_status)

    if conditions:
        query += " WHERE " + " AND ".join(conditions)
        count_query += " WHERE " + " AND ".join(conditions)

    # Add ORDER BY for consistent results with pagination
    query += " ORDER BY er.issued_at DESC "

    # Add LIMIT and OFFSET for pagination
    query += " LIMIT %s OFFSET %s"
    params.extend([per_page, offset])

    # --- Execute Queries ---
    cursor.execute(query, tuple(params))
    logs = cursor.fetchall()

    # Get total number of items for pagination
    # Exclude limit and offset for count query
    cursor.execute(count_query, tuple(params[:-2]))
    total_items = cursor.fetchone()['COUNT(er.id)']
    total_pages = math.ceil(total_items / per_page)

    cursor.close()
    db_conn.close()

    # Define available statuses for the filter dropdown (if applicable)
    # Customize as per your actual statuses
    available_statuses = ['Pending', 'Approved', 'Returned', 'Overdue']

    return render_template(
        "Equipment_logs.html",
        logs=logs,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        search_equipment=search_equipment,
        search_borrower=search_borrower,
        search_status=search_status,
        available_statuses=available_statuses
    )


@app.route('/eq_requests')
@admin_required
def view_eq_requests():
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)

    # Get the admin_role from the session.
    # Ensure 'admin_role' is set in the session during user login/authentication.
    admin_role = session.get('admin_role')

    cursor.execute("""
        SELECT
            r.id,
            e.name AS equipment_name,
            r.requester_name,
            r.purpose,
            r.requested_date,
            r.status,
            r.pixel_head_approval_status,  -- Fetch head approval status
            r.pixel_member_approval_status -- Fetch member approval status
        FROM equipment_requests r
        JOIN equipment e ON r.equipment_id = e.id
        ORDER BY r.requested_date DESC
    """)
    requests = cursor.fetchall()
    cursor.close()
    db_conn.close()  # Close the connection after use
    return render_template('Equipment_requests.html', requests=requests, admin_role=admin_role)


@app.route('/approve_reject_request', methods=['POST'])
@admin_required  # Ensure only authenticated admins can call this
def approve_reject_request():
    data = request.get_json()
    request_id = data.get('request_id')
    action = data.get('action')  # 'approve' or 'reject'
    approver_type = data.get('approver_type')  # 'pixel_head' or 'pixel_member'

    if not all([request_id, action, approver_type]):
        return jsonify({'success': False, 'message': 'Missing data'}), 400

    db_conn = get_db_connection()
    cursor = db_conn.cursor()  # Use a regular cursor for updates

    try:
        # Determine which status column to update based on approver_type
        if approver_type == 'pixel_head':
            status_column = 'pixel_head_approval_status'
        elif approver_type == 'pixel_member':
            status_column = 'pixel_member_approval_status'
        else:
            return jsonify({'success': False, 'message': 'Invalid approver type'}), 400

        new_approval_status = 'approved' if action == 'approve' else 'rejected'

        # Update the specific approval status (head or member)
        cursor.execute(f"UPDATE equipment_requests SET {status_column} = %s WHERE id = %s",
                       (new_approval_status, request_id))

        # Fetch current approval statuses to determine overall request status
        cursor.execute("""
            SELECT pixel_head_approval_status, pixel_member_approval_status
            FROM equipment_requests
            WHERE id = %s
        """, (request_id,))
        current_approvals = cursor.fetchone(
        )  # This will be a tuple (head_status, member_status)

        # Logic to update the overall 'status' of the request
        if current_approvals:
            head_status, member_status = current_approvals

            if head_status == 'approved' and member_status == 'approved':
                # If both are approved, set overall status to 'Approved'
                cursor.execute(
                    "UPDATE equipment_requests SET status = 'Approved' WHERE id = %s", (request_id,))
            elif head_status == 'rejected' or member_status == 'rejected':
                # If either is rejected, set overall status to 'Rejected'
                cursor.execute(
                    "UPDATE equipment_requests SET status = 'Rejected' WHERE id = %s", (request_id,))
            # If still pending for one, overall status remains 'Pending' (or whatever initial status is)

        db_conn.commit()
        return jsonify({'success': True, 'message': 'Request updated successfully'})

    except Exception as e:
        db_conn.rollback()  # Rollback on error
        print(f"Error updating request: {e}")
        return jsonify({'success': False, 'message': f'Server error: {e}'}), 500
    finally:
        cursor.close()
        db_conn.close()  # Always close the connection

# Example for mark_issued route (if it's also an AJAX call)


@app.route('/mark_issued', methods=['POST'])
@admin_required
def mark_issued():
    data = request.get_json()
    request_id = data.get('request_id')

    if not request_id:
        return jsonify({'success': False, 'message': 'Missing request ID'}), 400

    db_conn = get_db_connection()
    cursor = db_conn.cursor()

    try:
        cursor.execute(
            "UPDATE equipment_requests SET status = 'Issued' WHERE id = %s", (request_id,))
        db_conn.commit()
        return jsonify({'success': True, 'message': 'Request marked as issued'})
    except Exception as e:
        db_conn.rollback()
        print(f"Error marking as issued: {e}")
        return jsonify({'success': False, 'message': f'Server error: {e}'}), 500
    finally:
        cursor.close()
        db_conn.close()


@app.route('/request_equipment', methods=['GET', 'POST'])
def request_equipment():
    db_conn = get_db_connection()
    cursor = db_conn.cursor(dictionary=True)
    admin_username = session.get("admin_username")
    if request.method == 'POST':
        requester_name = request.form['requester_name']
        equipment_id = int(request.form['equipment_id'])
        purpose = request.form['purpose']
        requested_date = request.form['requested_date']

        cursor.execute("""
            INSERT INTO equipment_requests (equipment_id, requester_name, purpose, requested_date, status)
            VALUES (%s, %s, %s, %s, 'Pending')
        """, (equipment_id, requester_name, purpose, requested_date))
        db_conn.commit()
        cursor.close()
        return redirect(url_for('view_eq_requests'))

    cursor.execute("SELECT id, name FROM equipment WHERE available > 0")
    equipment = cursor.fetchall()
    cursor.close()
    return render_template('Equipment_request_form.html', equipment=equipment, admin_username=admin_username)


@app.context_processor
def inject_now():
    return {"now": datetime.now()}


if __name__ == "__main__":
    app.run(debug=True)
