from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_wtf.csrf import CSRFProtect, validate_csrf, CSRFError

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, func, select, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, selectinload, joinedload

import os, datetime, math 
from PIL import Image
from enum import IntEnum

# ----- Todo list ------
# TODO:
#    - make account page hidden for mobile users
#    - Make leaderboard on home page? or make leaderboard route

# --- Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

DATABASE_URL = 'sqlite:///' + os.path.join(BASE_DIR, 'keeleguesser.db')
SECRET_KEY = os.environ.get('KG_FLASK_SECRET') or 'change-this-secret-in-prod'
DELETED_USER_PASS = os.environ.get('KG_DELETED_USER_PASS') or "change-this-in-prod"
SERVER_NAME = os.environ.get('KG_SERVER_NAME') or "localhost:5000"

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
    IMPOSSIBLE = 6

DEFAULT_LOCATION = Location.ELSTEAD
DEFAULT_DIFFICULTY = Difficulty.MEDIUM
MAX_PHOTOS = 15 # in session
MAX_SUGGESTIONS = 100 # per user

# --- App and DB setup ---
app = Flask(__name__, static_folder='static')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SERVER_NAME'] = SERVER_NAME

csrf = CSRFProtect(app)

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

    highscores = relationship("Highscore", back_populates="user", cascade="all, delete-orphan")
    suggestions = relationship("Suggestion", back_populates="user")

class Highscore(Base):
    __tablename__ = "highscores"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    difficulty_id = Column(Integer)
    difficulty_name = Column(String(32))
    highscore = Column(Integer, nullable=False, default=0)
    perfect_streak = Column(Integer, nullable=False, default=0)
    location = Column(Integer, nullable=False, default=DEFAULT_LOCATION)

    user = relationship("User", back_populates="highscores")

class Suggestion(Base):
    __tablename__ = 'suggestions'
    id = Column(Integer, primary_key=True)
    content = Column(String(512), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    votes = Column(Integer, default=1)

    user = relationship("User", back_populates="suggestions")

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
    a = User(username=username, password_hash=h)
    s.add(a); s.commit(); s.close()
    return a

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

def delete_user():
    s = db_session()

    user = s.query(User).filter_by(username=session.get('user_username')).first()
    if not user:
        s.close()
        return # no need to panic, if the user doesn't exist, we won't worry

    deleted_user = s.query(User).filter_by(username="deleted_user").first()
    if not deleted_user:
        deleted_user = User(username="deleted_user", password_hash=generate_password_hash(DELETED_USER_PASS))
        s.add(deleted_user); s.commit()

    s.query(Suggestion).filter_by(user_id=user.id).update(
            {Suggestion.user_id: deleted_user.id},
            synchronize_session=False
            )

    s.delete(user)
    s.commit(); s.close()

def update_highscore():
    s = db_session()

    user = s.query(User).filter_by(username=session.get('user_username')).first()
    if not user:
        print("DEBUG: in update_highscore with no user")
        return 0

    # get the highscore for this difficulty
    if session.get('show_all_photos'):
        diff = None
    else:
        diff = session.get('difficulty')

    highscore = next((x for x in user.highscores if x.difficulty_id == diff), None)

    # No highscore for this difficulty
    if not highscore:
        difficulty_name = None
        difficulty_id = None
        for diff in Difficulty:
            if diff == session.get('difficulty') and not session.get('show_all_photos'):
                difficulty_name = diff.name
                difficulty_id = diff
        a = Highscore(
                user_id=user.id,
                difficulty_id=difficulty_id,
                difficulty_name=difficulty_name,
                highscore=session.get('current_score'),
                perfect_streak=session.get('current_streak'),
                location=session.get('location')
                )
        s.add(a); s.commit(); s.close()
        return session.get('current_score'), session.get('current_streak')

    ret = [0, 0]
    if session.get('current_score') and session.get('current_streak'):
        if highscore.highscore < session.get('current_score'):
            highscore.highscore = session.get('current_score')
            ret.append(session.get('current_score'))
        else:
            ret.append(highscore.highscore)
        if highscore.perfect_streak < session.get('current_streak'):
            highscore.perfect_streak = session.get('current_streak')
            ret.append(session.get('current_streak'))
        else:
            ret.append(highscore.perfect_streak)

    s.commit(); s.close()

    return ret

def get_leaderboard_data(diff, loc, limit=5):
    """
        diff can be None to get show_all_photos data

        returns:
            lb_data:
                streak: [{'username': ..., 'score': ..., 'order': ...},{...}] max 5
                highscore: [{'username': ..., 'score': ..., 'order':...},{...}] nax 5

            order: order is set to be the position of the given element in the list - to preserve order in js fetches
    """
    s = db_session()

    highscores = s.query(Highscore)\
                        .options(joinedload(Highscore.user))\
                        .filter_by(location=loc, difficulty_id=diff)\
                        .order_by(Highscore.highscore.desc())\
                        .limit(limit)\
                        .all()
    streaks = s.query(Highscore)\
                        .options(joinedload(Highscore.user))\
                        .filter_by(location=loc, difficulty_id=diff)\
                        .order_by(Highscore.perfect_streak.desc())\
                        .limit(limit)\
                        .all()

    s.close()

    data = {
            'streak': [{'username': x.user.username, 'score': x.perfect_streak, 'order': streaks.index(x) + 1} for x in streaks],
            'highscore': [{'username': x.user.username, 'score': x.highscore, 'order': highscores.index(x) + 1} for x in highscores]
    }

    return data

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

def change_password(username, password):
    if not username or not password:
        raise ValueError("Username or Password not provided");

    s = db_session()
    user = s.query(User).filter_by(username=username).first()

    if not user:
        s.close()
        raise ValueError("User doesn't exist")

    user.password_hash = generate_password_hash(password)
    s.commit(); s.close()

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

# ------ Context handlers -------
@app.context_processor
def inject_current_url():
    return {'_this': request.full_path or '/'}

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

@app.cli.command("change-pass")
@cli_login_required
def cli_change_pass():
    import getpass
    username = input("Username: ").strip()
    if not username:
        print("Username Required")
        return

    s = db_session()
    user = s.query(User).filter_by(username=username).first()
    s.close()

    if not user:
        print("User doesn't exist")
        return

    password = getpass.getpass("Password: ")
    password2 = getpass.getpass("Repeat: ")
    if password != password2:
        print("Passwords don't match")
        return

    try:
        change_password(username, password)
        print("Password changed")
    except Exception as e:
        print("Error: ", e)

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
    host = request.host.split(":")[0]
    domain = host.split(".")
    if len(domain) > 2:
        subdomain = domain[0]
        for loc in Location:
            if subdomain.upper() == loc.name:
                session['location'] = loc
                session['freeze_location'] = True;
                break

    return redirect('https://keeleguesser.beer/home') # so much simpler than filtering out the subdomain

@app.route('/home')
def home():
    if session.get('user_logged_in'): # make sure user exists
        if session.get('user_username') == "deleted_user":
            flash("You should not be logged in as a deleted user", "danger")
            return redirect(url_for('user_logout'))
        s = db_session()
        user = s.query(User).filter_by(username=session.get('user_username')).first()
        if not user:
            return redirect(url_for('user_logout'))

    return render_template('home.html')

@app.route('/user/delete', methods=['GET', 'POST'])
def user_delete():
    if request.method == "POST":
        if request.form.get('username') == session.get("user_username"):
            delete_user()
            flash("User deleted", "success")
            return redirect(url_for('home'))
        else:
            flash("Put in your correct username", "danger")
            return redirect(url_for('user_delete'))

    return render_template('delete_user.html')

@app.route('/suggestion/delete/', methods=['POST', 'DELETE'])
def delete_suggestion():
    if request.form.get('_method') != "DELETE":
        flash("An error on our end occurred. Try again later.", "danger")
        return redirect(url_for('account'))
    s = db_session()
    user = s.query(User).filter_by(username=session.get('user_username')).first()
    if not user and not session.get('admin_logged_in'):
        flash("An error occurred. Account not found.", "danger")
        return redirect(url_for('home'))

    suggestion_id = request.form.get('id', type=int)
    if suggestion_id:
        suggestion = s.query(Suggestion).get(suggestion_id)
        if suggestion and suggestion.user_id == user.id:
            s.delete(suggestion); s.commit()
            flash("Suggestion deleted", "success")
        else:
            flash("Suggestion not found", "danger")
    else:
        flash("An error occurred.", "danger")

    s.close()
    # TODO: add this into the actuall template args
    nxt = request.args.get('next') or url_for('home')
    return redirect(nxt)

@app.route('/admin/poll', methods=['GET', 'POST', 'DELETE'])
def admin_poll():
    # TODO
    flash("NOT IMPLEMENTED", "danger")
    return redirect(url_for('home'))

@app.route('/get/configopts', methods=['GET'])
def get_config_opts():
    data = {
        "location": {},
        "difficulty": {}
            }

    if not session.get('freeze_location'):
        for loc in Location:
            data["location"][loc.name] = loc
    else:
        data["location"]["Location Set"] = DEFAULT_LOCATION

    for difficulty in Difficulty:
        data["difficulty"][difficulty.name] = difficulty

    return jsonify(data), 200

@app.route('/sessioncfg/<int:location>/<int:difficulty>/<int:show_all_photos>')
def session_config(location, difficulty, show_all_photos):
    if location not in Location:
        flash("Please select a valid location", "warning")
        return redirect(url_for('home'))
    if difficulty not in Difficulty:
        flash("Please select a valid difficulty", "warning")
        return redirect(url_for('home'))
    if show_all_photos not in [0, 1]:
        flash("Please don't take the piss", "danger")
        return redirect(url_for('home'))

    # on first login neither are set so always true
    if session.get('location') != location or session.get('difficulty') != difficulty or \
            session.get('current_photo_index') >= len(session.get('photo_list')):
        session['current_score'] = 0
        session['current_streak'] = 0
        session['current_photo_index'] = 0
        session.pop('photo_list', None)

    if session.get('freeze_location'):
        session['location'] = location
    session['difficulty'] = difficulty
    session['show_all_photos'] = show_all_photos
    for loc in Location:
        if loc == location:
            session['location_text'] = f"{loc.name[0]}{loc.name[1:].lower()}"
            break

    return redirect(url_for('play'))

@app.route('/play/next')
def inc_photo_index(): # prevent user refresh from updating photo index
    session['current_photo_index'] = session.get('current_photo_index') + 1
    return redirect(url_for('play'))

@app.route('/play')
def play():
    if not session.get('difficulty') and session.get('location'):
        return redirect(url_for('home'))
    # Randomize selection server-side: pick one random photo
    s = db_session()
    if not session.get('photo_list'):
        # TODO: use a random id starting point with overflow modulo instead of func.random() - Performance
        if session.get('show_all_photos'):
            session['photo_list'] = [x[0] for x in\
                    s.query(Photo.id)
                        .filter_by(location=session.get('location'))
                        .order_by(func.random())
                        .limit(MAX_PHOTOS)
                        .all()]
        else:
            session['photo_list'] = [x[0] for x in\
                    s.query(Photo.id)
                        .filter_by(location=session.get('location'), difficulty=session.get('difficulty'))
                        .order_by(func.random())
                        .limit(MAX_PHOTOS)
                        .all()]

        session['current_photo_index'] = 0

    if len(session.get('photo_list')) == 0:
        s.close()
        return redirect(url_for('no_photos'))

    if session.get('current_photo_index') >= MAX_PHOTOS or session.get('current_photo_index') >= len(session.get('photo_list')):
        s.close()
        return redirect(url_for('end_of_session'))

    photo = s.query(Photo).filter_by(id=session.get('photo_list')[session.get('current_photo_index')]).first()

    if not photo:
        flash("An error has occurred, please try again later", "danger")
        s.close()
        return redirect(url_for('home'))

    for diff in Difficulty:
        if diff == photo.difficulty:
            difficulty = diff.name

    s.close()

    return render_template('play.html', photo=photo, difficulty=difficulty)

@app.route('/no_photos', methods=['GET'])
def no_photos():
    return render_template('no_photos.html');

@app.route('/user', methods=['GET'])
@user_login_required
def account():
    s = db_session()
    user = s.query(User).filter_by(username=session.get('user_username')).first()
    if not user:
        s.close()
        flash("User not found.", "danger")
        return redirect(url_for('user_login'))

    suggestions = [(x.content, x.votes, x.id) for x in user.suggestions]

    highscores = [(x.highscore, x.perfect_streak, x.difficulty_name) for x in user.highscores]

    s.close()
    return render_template('user_account.html', user=user, suggestions=suggestions, highscores=highscores)

@app.route('/suggestion', methods=['GET', 'POST'])
@user_login_required
def suggestion():
    if not session.get('user_logged_in'):
        flash("You're a cheeky one, I'll grant you. But you need to piss off now.", "danger")
        return redirect(url_for('user_login'))

    s = db_session()
    can_submit = False

    user_id = s.query(User.id).filter_by(username=session.get('user_username')).scalar()
    if not user_id:
        s.close()
        flash("Okay... how in God's name did you get this far?????", "success")
        return redirect(url_for('user_login'))

    if s.query(Suggestion).filter_by(user_id=user_id).count() < MAX_SUGGESTIONS:
        can_submit = True

    s.close()

    if request.method == 'POST':
        if not can_submit:
            flash("You've exceeded the maximum number of suggestions", "danger")
            return redirect(url_for('account'))
        content = request.form.get('suggestion-content', '').strip()

        try:
            add_suggestion(user_id, content)
            flash('Your suggestion has been added!', 'success')
        except ValueError as e:
            flash("An error occurred, please try again later... but like... much later, cos something is broken broken", "danger")
            print(e)

    return render_template('suggestion.html', can_submit=can_submit)

@app.route('/nomorephotos', methods=['GET'])
def end_of_session():
    return render_template('end_of_session.html')

@app.route('/admin/suggestions', methods=['GET'])
@login_required
def admin_suggestions():
    s = db_session()
    suggestions = [[x.content, x.user.username, x.id] for x in s.execute(select(Suggestion).options(selectinload(Suggestion.user))).scalars().all()]
    s.close()
    return render_template('admin_suggestions.html', suggestions=suggestions)

@app.route('/guess', methods=['POST'])
@csrf.exempt # manually for json
def guess():
    data = request.json
    if not data:
        return jsonify({"error":"No JSON payload"}), 400

    csrf_token = data.get('csrf_token')
    try:
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({"error": "Invalid CSRF Token"}), 400

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
        WIN_DIST = 10
    elif session.get('difficulty') == Difficulty.MEDIUM:
        WIN_DIST = 7
    elif session.get('difficulty') == Difficulty.HARD:
        WIN_DIST = 4
    elif session.get('difficulty') == Difficulty.HARDER:
        WIN_DIST = 2
    elif session.get('difficulty') == Difficulty.HARDEST:
        WIN_DIST = 1
    elif session.get('difficulty') == Difficulty.IMPOSSIBLE:
        WIN_DIST = 0.1
    else:
        flash("Please select a difficulty to play", "danger")
        return jsonify({"error": "No difficulty selected"}), 400

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
        points = 0

    # ================================================

    if points >= MAX_POINTS:
        points = MAX_POINTS
        session['current_streak'] = session.get('current_streak') + 1
    else:
        session['current_streak'] = 0

    session['current_score'] = session.get('current_score') + int(points)
    if session.get('user_logged_in'):
        update_highscore()

    return jsonify({
        "distance_m": round(dist_m,1),
        "points": math.floor(points),
        "true_lat": true_lat,
        "true_lng": true_lng,
        "current_score": session.get('current_score'),
        "current_streak": session.get('current_streak')
    })

@app.route('/user/logout')
def user_logout():
    session.pop('user_logged_in', None)
    session.pop('user_username', None)
    session.pop('user_highscore', None)
    flash('Logged out', 'info')
    return redirect(url_for('home'))

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        s = db_session()
        user = s.query(User).filter_by(username=username).first()
        s.close()

        if user and check_password_hash(user.password_hash, password):
            session['user_logged_in'] = True
            session['user_username'] = username
            update_highscore()

            flash('Logged in successfully', 'success')
            nxt = request.args.get('next') or url_for('home')
            return redirect(nxt)

        flash('Dodgy Credentials.', 'danger')
    return render_template('login.html')

@app.route('/user/create', methods=['GET', 'POST'])
def user_create():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        try:
            create_user(username, password)
            flash('Account Created', 'success')
            session['user_logged_in'] = True
            session['user_username'] = username
            update_highscore()
            return redirect(url_for('home'))
        except ValueError as e:
            flash('Failed to create account. Username probably taken.', 'danger')
    return render_template('create_user.html')

@app.route('/get/leaderboard/<int:difficulty>/<int:location>/<int:show_all_photos>', methods=['GET'])
def get_leaderboard(difficulty, location, show_all_photos):
    if show_all_photos not in [0, 1]:
        return jsonify({'error': 'Bad show_all_photos value'}), 400

    if show_all_photos == 1:
        lb_data = get_leaderboard_data(None, location)
    else:
        lb_data = get_leaderboard_data(difficulty, location)

    """
    lb_data:
        streak: [{'username': ..., 'score': ...},{...}] max 5
        highscore: [{'username': ..., 'score': ...},{...}] nax 5

    """
    return jsonify(lb_data), 200




@app.route('/get/username/<username>')
def get_username(username):
    s = db_session()
    user = s.query(User).filter_by(username=username).first()
    s.close()
    if user:
        return jsonify({
            'isUser': True
        }), 200
    else:
        return jsonify({
            'isUser': False
        }), 200

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
    return redirect(url_for('home'))

@app.route('/admin', methods=['GET','POST'])
@login_required
def admin():
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        lat = request.form.get('lat', type=float)
        lng = request.form.get('lng', type=float)
        loc = request.form.get('location', type=int)
        diff = request.form.get('difficulty', type=int)

        if (not loc) and (not diff):
            flash("Using location and difficulty defaults", "info")
            loc = DEFAULT_LOCATION
            diff = DEFAULT_DIFFICULTY
        elif not loc:
            flash("Using default location: " + DEFAULT_LOCATION.name[0] + LOCATION.name[1:].lower(), "info")
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
            p = Photo(filename=filename_full, lat=float(lat), lng=float(lng), location=int(loc), difficulty=int(diff))
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
    search_help = None
    if "login" in request.path:
        search_help = "/user/login"
    if "user" in request.path:
        search_help = "/account"

    if search_help:
        flash("Maybe you meant: " + search_help, "warning")

    return render_template('404.html'), 404

@app.route("/favicon.ico")
def serve_favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')
