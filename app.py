from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, func, select, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
import os, datetime, math, random
from PIL import Image
from enum import IntEnum

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE_URL = 'sqlite:///' + os.path.join(BASE_DIR, 'geocampus.db')
SECRET_KEY = os.environ.get('GEO_SECRET') or 'change-this-secret-in-prod'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# ------- Global `macros` ------------
class Location(IntEnum):
    KEELE = 1
    ELSTEAD = 2

class Difficulty(IntEnum):
    EASY = 1
    MEDIUM = 2
    HARD = 3
    HARDER = 4
    HARDEST = 5

DEFAULT_LOCATION = Location.ELSTEAD;
DEFAULT_DIFFICULTY = Difficulty.MEDIUM;

# --- App and DB setup ---
app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# --- Difficultyls ---
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
    location = Column(Integer, nullable=False)
    difficulty = Column(Integer, nullable=False)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    highscore = Column(Integer, default=0)

class Suggestion(Base):
    __tablename__ = 'suggestions'
    id = Column(Integer, primary_key=True)
    content = Column(String(512), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    votes = Column(Integer, default=1)

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

def create_user(username, password, score=0):
    s = db_session()
    if s.query(User).filter_by(username=username).first():
        s.close()
        raise ValueError("Usename already exists")
    h = generate_password_hash(password)
    a = User(username=username, password_hash=h, highscore=score)
    s.add(a); s.commit(); s.close()

def add_suggestion(user_id, content):
    s = db_session()
    if not s.query(User).filter_by(id=user_id).first():
        s.close()
        raise ValueError("User doesn't exist")
    if len(content) > 511:
        s.close()
        raise ValueError("Content too long")

    a = Suggestion(content=content, user_id=user_id)
    s.add(a); s.commit(); s.close()

def cli_login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        import getpass
        s = db_session()

        if not s.query(Admin).first():
            s.close()
            return fn(*args, **kwargs)

        print("You must log in first.")
        username = input("Admin Username: ").strip()
        password = getpass.getpass("Admin Password: ")
        admin = s.query(Admin).filter_by(username=username).first()
        s.close()

        if admin and check_password_hash(admin.password_hash, password):
            print("Logged in Successfully")
            return fn(*args, **kwargs)

        print("Failed to login")
    return wrapper

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get('admin_logged_in'):
            return fn(*args, **kwargs)
        flash("Please log in as admin to access that page.", "warning")
        return redirect(url_for('admin_login', next=request.path))
    return wrapper

def user_login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get('user_logged_in'):
            return fn(*args, **kwargs)
        flash("Ah ah ah. You need to be logged in!", "warning")
        return redirect(url_for('user_login', next=request.path))
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
@cli_login_required
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

@app.cli.command("show-admins")
@cli_login_required
def cli_show_admins():
    s = db_session()
    admins = s.execute(select(Admin.username)).all()
    print()
    print("Existing Admins: ")
    for admin in admins:
        print(admin[0])
    print()
    s.close()

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('home'))

@app.route('/home')
def home():
    return render_template('home.html');

@app.route('/get/configopts', methods=['GET'])
def get_config_opts():
    data = {
        "location": {},
        "difficulty": {}
            }
    for loc in Location:
        data["location"][loc.name] = loc 
    for difficulty in Difficulty:
        data["difficulty"][difficulty.name] = difficulty

    return jsonify(data), 200

@app.route('/sessioncfg/<int:location>/<int:difficulty>')
def session_config(location, difficulty):
    if location not in Location:
        flash("Please select a valid location", "warning")
        return redirect(url_for('home'))
    if difficulty not in Difficulty:
        flash("Please select a valid difficulty", "warning")
        return redirect(url_for('home'))

    # on first login neither are set so always true
    if session.get('location') != location or session.get('difficulty') != difficulty:
        session['current_score'] = 0
        session['seen_photos'] = []
    session['location'] = location
    session['difficulty'] = difficulty
    for loc in Location:
        if loc == location: 
            session['location_text'] = f"{loc.name[0]}{loc.name[1:].lower()}"

    return redirect(url_for('play'))


@app.route('/play')
def play():
    # Randomize selection server-side: pick one random photo
    s = db_session()
    print(session.get('difficulty'))
    print(s.query(func.count(Photo.id)).filter_by(location=session.get('location'), difficulty=session.get('difficulty')).scalar())
    if len(session.get('seen_photos')) >= s.query(func.count(Photo.id)).filter_by(location=session.get('location'), difficulty=session.get('difficulty')).scalar():
        s.close()

        if len(session.get('seen_photos')) == 0: # if they haven't seen any photos then there prolly none there ay
            return render_template('no_photos.html')

        return redirect(url_for('seen_all_photos'))

    photo = s.query(Photo).filter_by(location=session.get('location'), difficulty=session.get('difficulty')).order_by(func.random()).first()
    print(photo);
    while photo.id in session.get('seen_photos'):
        photo = s.query(Photo).filter_by(location=session.get('location'), difficulty=session.get('difficulty')).order_by(func.random()).first()

    s.close()

    session['seen_photos'].append(photo.id)

    return render_template('play.html', photo=photo)

@app.route('/suggestion', methods=['GET', 'POST'])
@user_login_required
def suggestion():
    if not session.get('user_logged_in'):
        flash("You're a cheeky one, I'll grant you. But you need to piss off now.", "danger")
        return redirect(url_for('user_login'))

    if request.method == 'POST':
        s = db_session()
        user_id = s.query(User.id).filter_by(username=session.get('user_username')).scalar()
        s.close()
        if not user_id:
            flash("Okay... how in God's name did you get this far?????", "Warning");
            return redirect(url_for('user_login'))

        content = request.form.get('suggestion-content', '').strip()
        try:
            add_suggestion(user_id, content)
            flash('Your suggestion has been added!', 'success')
        except ValueError as e:
            flash("Failed to add your suggestion. No idea why...", "danger")
            print(e)
    return render_template('suggestion.html')

@app.route('/nomorephotos', methods=['GET'])
def seen_all_photos():
    return render_template('seen_all_photos.html')

@app.route('/admin/suggestions', methods=['GET', 'POST'])
@login_required
def admin_suggestions():
    if request.method == "POST":
        if not request.id:
            flash("I need an id dog...", "danger")
            return redirect(url_for('admin_suggestions'))
        s = db_session()
        suggestion = s.query(Suggestion).filter_by(id=request.id).first()
        s.delete(suggestion); s.commit(); s.close();
        flash("Deleted suggestion", "success")
        return redirect(url_for('admin_suggestions'))

    s = db_session()
    suggestions = [[x] for x in s.execute(select(Suggestion)).scalars().all()]
    for suggestion in suggestions:
        suggestion.append(s.query(User.username).filter_by(id=suggestion[0].user_id).first()[0])
    s.close()
    return render_template('admin_suggestions.html', suggestions=suggestions)

@app.route('/guess', methods=['POST'])
def guess():
    data = request.json
    if not data:
        return jsonify({"error":"No JSON payload"}), 400
    photo_id = data.get('photo_id')
    guess_lat = data.get('guess_lat')
    guess_lng = data.get('guess_lng')
    box= data.get('box')
    if photo_id is None or guess_lat is None or guess_lng is None or box is None:
        return jsonify({"error":"Missing fields"}), 400
    s = db_session()
    photo = s.query(Photo).get(photo_id)
    s.close()
    if not photo:
        return jsonify({"error":"Photo not found"}), 404
    true_lat, true_lng = photo.lat, photo.lng
    dist_m = haversine(true_lat, true_lng, float(guess_lat), float(guess_lng))

    # ============== Calculate Points ================
    MAX_POINTS = 5000
    if session.get('difficulty') == Difficulty.EASY:
        WIN_DIST = 7
    elif session.get('difficulty') == Difficulty.NORMAL:
        WIN_DIST = 5
    elif session.get('difficulty') == Difficulty.HARD:
        WIN_DIST = 3
    elif session.get('difficulty') == Difficulty.VERYHARD:
        WIN_DIST = 1
    else:
        flash("Please select a difficulty to play", "Danger")
        return redirect(url_for('home'))

    if dist_m < WIN_DIST:
        points = MAX_POINTS
    else:
        dist_topLeft = haversine(true_lat, true_lng, float(box['topLeftLat']), float(box['topLeftLng']))
        dist_topRight = haversine(true_lat, true_lng, float(box['topRightLat']), float(box['topRightLng']))
        dist_bottomLeft = haversine(true_lat, true_lng, float(box['bottomLeftLat']), float(box['bottomLeftLng']))
        dist_bottomRight = haversine(true_lat, true_lng, float(box['bottomRightLat']), float(box['bottomRightLng']))

        furthest_distance = max(dist_topLeft, dist_topRight, dist_bottomLeft, dist_bottomRight)

        # points lost per meter distance
        pts_per_m = MAX_POINTS/furthest_distance
        points = MAX_POINTS - (pts_per_m * dist_m)

    if points < 0:
        points = 0;

    # ================================================

    temp_highscore = 0;
    session['current_score'] = session.get('current_score') + int(points);
    if session.get('user_logged_in') and session.get('user_highscore') < session.get('current_score'):
        session['user_highscore'] = session.get('current_score'); 
        temp_highscore = session.get('user_highscore')
        
    return jsonify({
        "distance_m": round(dist_m,1),
        "points": math.floor(points),
        "true_lat": true_lat,
        "true_lng": true_lng,
        "current_score": session.get('current_score'),
        'highscore': temp_highscore
    })

@app.route('/user/logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_username', None)
    session.pop('user_highscore', None)
    flash('Logged out', 'info')
    return redirect(url_for('play'))

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        current_score = session.get('current_score')
        if not current_score:
            current_score = 0;

        s = db_session()
        user = s.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_logged_in'] = True
            session['user_username'] = username
            session['current_score'] = current_score

            if current_score > user.highscore:
                user.highscore = current_score
                s.commit(); s.close()

            session['user_highscore'] = user.highscore
            flash('Logged in successfully', 'success')
            nxt = request.args.get('next') or url_for('home')
            return redirect(nxt)
        s.close()
        flash('Dodgy Credentials.', 'danger')
    return render_template('login.html')

@app.route('/user/create', methods=['GET', 'POST'])
def user_create():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        try:
            create_user(username, password, score=session.get('current_score'));
            flash('Account Created', 'success')
            return redirect(url_for('home'))
        except ValueError as e:
            flash('Failed to create account. Username probably taken.', 'danger')

    return render_template('create_user.html')

@app.route('/get/username/<username>')
def get_username(username):
    s = db_session()
    user = s.query(User).filter_by(username=username).first()
    s.close()
    if user:
        return jsonify({
            'isUser': True 
        })
    else:
        return jsonify({
            'isUser': False
        })

@app.route('/reset')
def reset_photos():
    session['seen_photos'] = []
    session['current_score'] = 0
    return redirect(url_for('play'))

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
            nxt = request.args.get('next') or url_for('admin')
            return redirect(nxt)
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash('Logged out', 'info')
    return redirect(url_for('play'))

@app.route('/admin', methods=['GET','POST'])
@login_required
def admin():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        lat = request.form.get('lat')
        lng = request.form.get('lng')
        loc = request.form.get('location')
        diff = request.form.get('difficulty')

        print(lat, lng, loc, diff)

        if (not loc) and (not diff):
            flash("Using location and difficulty defaults", "info");
            loc = DEFAULT_LOCATION;
            diff = DEFAULT_DIFFICULTY;
        elif not loc:
            flash("Using default location: " + DEFAULT_LOCATION.name[0] + DEFAULT_LOCATION.name[1:].lower(), "info")
            loc = DEFAULT_LOCATION
        elif not diff:
            flash("Using default difficulty: " + DEFAULT_DIFFICULTY.name.lower(), "info")
            diff = DEFAULT_DIFFICULTY


        if not lat or not lng:
            flash('You must click the map to set the photo location before uploading.', 'danger')
            return redirect(request.url)

        file = request.files['photo']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # add timestamp to filename to avoid collisions
            filename = f"{int(datetime.datetime.utcnow().timestamp())}_{os.path.splitext(filename)[0]}"
            filename_full = filename + ".jpeg"
            tmp_file = os.path.join(app.config['UPLOAD_FOLDER'], filename + "_upload")
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename_full)
            file.save(tmp_file)
            # optional: resize/validate

            try:
                with Image.open(tmp_file) as img:
                    img.save(path, format="JPEG")
            finally:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)

            s = db_session()
            p = Photo(filename=filename_full, lat=float(lat), lng=float(lng), location=loc, difficulty=diff)
            s.add(p); s.commit(); s.close()
            flash('Photo uploaded and saved.', 'success')
            return redirect(url_for('admin'))
        else:
            flash('Invalid file type', 'danger')
            return redirect(request.url)
    # GET
    return render_template('upload.html')

@app.route('/admin/delete/<int:photo_id>', methods=['POST'])
@login_required
def admin_delete(photo_id):
    s = db_session()
    photo = s.query(Photo).get(photo_id)
    if not photo:
        s.close()
        flash('Not found', 'danger')
        return redirect(url_for('admin'))
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
    return redirect(url_for('admin'))

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

