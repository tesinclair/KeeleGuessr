from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, func
from sqlalchemy.orm import sessionmaker, declarative_base
import os, datetime, math, random
from PIL import Image

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE_URL = 'sqlite:///' + os.path.join(BASE_DIR, 'geocampus.db')
SECRET_KEY = os.environ.get('GEO_SECRET') or 'change-this-secret-in-prod'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- App and DB setup ---
app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# --- Models ---
class Admin(Base):
    __tablename__ = 'admins'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

class Photo(Base):
    __tablename__ = 'photos'
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    caption = Column(String(255))
    lat = Column(Float, nullable=False)
    lng = Column(Float, nullable=False)
    uploaded_at = Column(DateTime, default=func.now())

Base.metadata.create_all(engine)

# --- Helpers ---
def db_session():
    return SessionLocal()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def create_admin(username, password):
    s = db_session()
    if s.query(Admin).filter_by(username=username).first():
        s.close()
        raise ValueError("Admin already exists")
    h = generate_password_hash(password)
    a = Admin(username=username, password_hash=h)
    s.add(a); s.commit(); s.close()

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get('admin_logged_in'):
            return fn(*args, **kwargs)
        flash("Please log in as admin to access that page.", "warning")
        return redirect(url_for('admin_login', next=request.path))
    return wrapper

# Haversine distance in meters
def haversine(lat1, lon1, lat2, lon2):
    R = 6371000  # meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*(math.sin(dlambda/2)**2)
    c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

# --- CLI helper via flask commands ---
@app.cli.command("create-admin")
def cli_create_admin():
    import getpass
    username = input("Admin username: ").strip()
    if not username:
        print("username required")
        return
    password = getpass.getpass("Password: ")
    password2 = getpass.getpass("Password (again): ")
    if password != password2:
        print("Passwords don't match.")
        return
    try:
        create_admin(username, password)
        print("Admin created.")
    except Exception as e:
        print("Error:", e)

# --- Routes ---
@app.route('/')
def index():
    # landing -> play
    return redirect(url_for('play'))

@app.route('/play')
def play():
    # Randomize selection server-side: pick one random photo
    s = db_session()
    # SQLite random: ORDER BY RANDOM() LIMIT 1
    photo = s.query(Photo).order_by(func.random()).first()
    s.close()
    if not photo:
        return render_template('no_photos.html')
    return render_template('play.html', photo=photo)

@app.route('/guess', methods=['POST'])
def guess():
    data = request.json
    if not data:
        return jsonify({"error":"No JSON payload"}), 400
    photo_id = data.get('photo_id')
    guess_lat = data.get('lat')
    guess_lng = data.get('lng')
    if photo_id is None or guess_lat is None or guess_lng is None:
        return jsonify({"error":"Missing fields"}), 400
    s = db_session()
    photo = s.query(Photo).get(photo_id)
    s.close()
    if not photo:
        return jsonify({"error":"Photo not found"}), 404
    true_lat, true_lng = photo.lat, photo.lng
    dist_m = haversine(true_lat, true_lng, float(guess_lat), float(guess_lng))
    # Scoring: example simple function: score = max(0, round(10000 - distance)/100) but we'll do:
    # 5000m -> 0, 0m -> 5000 points. Linear clamp.
    max_points = 5000
    points = max(0, round(max_points * (1 - min(dist_m, max_points)/max_points)))
    return jsonify({
        "distance_m": round(dist_m,1),
        "points": points,
        "true_lat": true_lat,
        "true_lng": true_lng
    })

# --- Admin routes ---
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        s = db_session()
        admin = s.query(Admin).filter_by(username=username).first()
        s.close()
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash('Logged in successfully', 'success')
            nxt = request.args.get('next') or url_for('admin_upload')
            return redirect(nxt)
        flash('Invalid credentials', 'danger')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Logged out', 'info')
    return redirect(url_for('admin_login'))

@app.route('/admin/upload', methods=['GET','POST'])
@login_required
def admin_upload():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['photo']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # add timestamp to filename to avoid collisions
            name = f"{int(datetime.datetime.utcnow().timestamp())}_{filename}"
            path = os.path.join(app.config['UPLOAD_FOLDER'], name)
            file.save(path)
            # optional: resize/validate
            try:
                img = Image.open(path)
                img.verify()
            except Exception:
                os.remove(path)
                flash("Uploaded file is not a valid image", "danger")
                return redirect(request.url)
            # get lat/lng from form
            lat = request.form.get('lat')
            lng = request.form.get('lng')
            caption = request.form.get('caption','')
            if not lat or not lng:
                # delete file if no location selected
                os.remove(path)
                flash('You must click the map to set the photo location before uploading.', 'danger')
                return redirect(request.url)
            s = db_session()
            p = Photo(filename=name, caption=caption, lat=float(lat), lng=float(lng))
            s.add(p); s.commit(); s.close()
            flash('Photo uploaded and saved.', 'success')
            return redirect(url_for('admin_upload'))
        else:
            flash('Invalid file type', 'danger')
            return redirect(request.url)
    # GET
    s = db_session()
    photos = s.query(Photo).order_by(Photo.uploaded_at.desc()).all()
    s.close()
    return render_template('upload.html', photos=photos)

@app.route('/admin/delete/<int:photo_id>', methods=['POST'])
@login_required
def admin_delete(photo_id):
    s = db_session()
    photo = s.query(Photo).get(photo_id)
    if not photo:
        s.close()
        flash('Not found', 'danger')
        return redirect(url_for('admin_upload'))
    # delete file
    path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
    s.delete(photo)
    s.commit()
    s.close()
    flash('Deleted', 'info')
    return redirect(url_for('admin_upload'))

# route to serve uploaded images (static does that already but here's explicit)
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Error handlers, small helpers ---
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

# --- Run (if executed directly) ---
if __name__ == '__main__':
    app.run(debug=True)

