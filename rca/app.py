# app.py - FINAL VERSION with Flask-Login and Flask-Bcrypt

import os
import eventlet
import datetime

from flask import Flask, render_template, request, session, redirect, url_for, current_app
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# NEW IMPORTS FOR SECURE AUTHENTICATION
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt 

# Patch standard libraries
eventlet.monkey_patch() 

# --- CONFIGURATION ---
app = Flask(__name__, static_folder='static')

app.config['SECRET_KEY'] = 'your_super_secret_key_890' 

# Database Configuration 
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/realtime_chat_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File Upload Configuration
UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='eventlet', manage_session=False) 

# Initialize Flask-Bcrypt
bcrypt = Bcrypt(app) 

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- LOGIN MANAGER USER LOADER ---
# Required for Flask-Login to reload the user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- GLOBAL STATE (Non-Persistent Tracking) ---
users_in_rooms = {} 
user_focus = {}
user_sid_map = {} 

# --- DATABASE MODELS ---
# UserMixin provides methods like is_authenticated, get_id, etc., required by Flask-Login
class User(db.Model, UserMixin): 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # Bcrypt requires this column to store the hashed password
    password_hash = db.Column(db.String(128)) 
    
    def set_password(self, password):
        # Use bcrypt to hash the password
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8') 
        
    def check_password(self, password):
        # Use bcrypt to check the password
        return bcrypt.check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_name = db.Column(db.String(50), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))

class DMMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='dms_sent', lazy=True)
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='dms_received', lazy=True)


# --- HELPER FUNCTIONS ---

def authenticated_only(f):
    """
    Decorator to ensure Flask app context is loaded for SocketIO events 
    and verifies the current_user is authenticated.
    """
    def wrapped(*args, **kwargs):
        with app.app_context(): 
            # Use current_user.is_authenticated provided by Flask-Login
            if current_user.is_authenticated:
                return f(*args, **kwargs)
            else:
                print("SocketIO: Connection refused - User not logged in.")
                return False 
    return wrapped

def update_user_list(room):
    """Calculates and broadcasts the list of users in a given room (Presence Indicator)."""
    room_users = sorted(list(set([
        info['username'] for sid, info in users_in_rooms.items() 
        if info.get('room') == room
    ])))
    socketio.emit('users_list', {'users': room_users}, room=room)


# --- FLASK ROUTES (Standard HTTP) ---

@app.route('/')
@login_required # Requires the user to be logged in
def index():
    return render_template('index.html', username=current_user.username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already taken.")
            
        new_user = User(username=username)
        new_user.set_password(password) # Uses Bcrypt hashing
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Flask-Login function to start the user session
            login_user(user) 
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password.")
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Flask-Login function to end the session
    logout_user() 
    session.pop('room', None) # Clear the room session key manually
    return redirect(url_for('login'))

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    room = request.form.get('room')
    if not room:
        return redirect(url_for('index'))
    
    # Store the room name in the Flask session 
    session['room'] = room 
    return render_template('chat.html', username=current_user.username, room=room)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return 'No file part', 400
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
        
    username = current_user.username
    room = request.form.get('room')
    
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        file_url_path = os.path.join('uploads', filename)
        
        socketio.emit('file_message', {
            'user': username, 
            'file_url': url_for('static', filename=file_url_path, _external=True),
            'filename': filename
        }, room=room)
        
        return 'File uploaded successfully', 200
    return 'Upload failed', 500


# --- SOCKETIO EVENT HANDLERS (Real-Time Communication) ---

@socketio.on('connect')
def handle_connect():
    """Handles a new client connecting via WebSocket."""
    user_focus[request.sid] = True
    print(f'Client connected: {request.sid}')

@socketio.on('join')
@authenticated_only 
def on_join(data):
    """Client sends this event to join a specific room."""
    # Use current_user for authenticated data
    username = current_user.username
    user_id = current_user.id
    room = session.get('room') # Room must be stored in the session via the /chat route
    
    if not room:
        print("Error: User session does not contain room name.")
        return

    join_room(room)
    
    # Store user tracking data
    users_in_rooms[request.sid] = {'username': username, 'room': room, 'user_id': user_id}
    user_sid_map[user_id] = request.sid 

    # Chat History
    history = Message.query.filter_by(room_name=room) \
                           .order_by(Message.timestamp.asc()) \
                           .limit(50) \
                           .all()

    formatted_history = [{
        'user': msg.user.username, 
        'text': msg.content
    } for msg in history]

    emit('history', formatted_history, room=request.sid)

    # Welcome and Broadcast
    emit('message', {'user': 'System', 'text': f'Welcome to the room **{room}**, {username}!'}, room=request.sid)
    emit('message', {'user': 'System', 'text': f'**{username}** has joined the chat.'}, room=room, skip_sid=request.sid)

    # Presence Indicator Update
    update_user_list(room)

@socketio.on('chat_message')
@authenticated_only 
def handle_chat_message(data):
    """Handles an incoming public room text message."""
    username = current_user.username
    user_id = current_user.id
    room = session.get('room')
    message_text = data.get('text')
    
    if user_id and room and message_text:
        # Save to Database (Chat History)
        new_message = Message(user_id=user_id, room_name=room, content=message_text)
        db.session.add(new_message)
        db.session.commit()
        
        # Broadcast Message
        emit('message', {
            'user': username, 
            'text': message_text
        }, room=room)
        
        # Notifications
        for sid, info in users_in_rooms.items():
            if info['room'] == room and sid != request.sid and not user_focus.get(sid, True):
                socketio.emit('notification', {
                    'room': room,
                    'user': username,
                    'text': message_text
                }, room=sid)

@socketio.on('private_message')
@authenticated_only 
def handle_private_message(data):
    """Handles an incoming private message (DM)."""
    sender_id = current_user.id
    sender_username = current_user.username
    
    target_username = data.get('target_username')
    message_text = data.get('text')
    
    receiver = User.query.filter_by(username=target_username).first()
    
    if not receiver or not message_text:
        emit('dm_sent', {'sender': 'System', 'text': 'User not found or message empty.'}, room=request.sid)
        return 
        
    receiver_id = receiver.id
    target_sid = user_sid_map.get(receiver_id)

    # Save to database (DM History)
    new_dm = DMMessage(sender_id=sender_id, receiver_id=receiver_id, content=message_text)
    db.session.add(new_dm)
    db.session.commit()
    
    dm_data = {
        'sender': sender_username,
        'text': message_text,
        'target': target_username
    }
    
    # Send message to receiver (if connected)
    if target_sid:
        emit('dm_received', dm_data, room=target_sid)
    
    # Send confirmation back to sender
    emit('dm_sent', dm_data, room=request.sid)


@socketio.on('user_focus_change')
@authenticated_only 
def handle_user_focus_change(data):
    """Updates user's focus state for notification logic."""
    user_focus[request.sid] = data.get('focused', True)

@socketio.on('disconnect')
def handle_disconnect():
    """Handles a client disconnecting."""
    sid = request.sid
    # We must run cleanup logic inside the app context for proper access
    with app.app_context():
        if sid in users_in_rooms:
            info = users_in_rooms.pop(sid)
            room = info['room']
            username = info['username']
            user_id = info['user_id']
            
            user_focus.pop(sid, None)
            if user_id in user_sid_map and user_sid_map[user_id] == sid:
                del user_sid_map[user_id]

            emit('message', {'user': 'System', 'text': f'**{username}** has left the chat.'}, room=room)
            update_user_list(room)


# --- RUN APPLICATION ---
if __name__ == '__main__':
    # Initialize DB tables (Run this once)
    with app.app_context():
        db.create_all() 
    
    print(f"Starting server on http://127.0.0.1:5000")
    socketio.run(app, debug=True, port=5000)