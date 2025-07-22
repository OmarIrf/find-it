from flask import Blueprint, render_template, redirect, url_for, flash, session, request, abort, jsonify
from .forms import LoginForm, RegisterForm, ItemForm
from .models import db, User, Item, Message
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from app import socketio
from flask_socketio import emit, join_room
from sqlalchemy.orm import joinedload
from sqlalchemy import or_
import re

routes = Blueprint("routes", __name__)
connected_users = set()
# Index Route
@routes.route("/")
def index():
    recent_items = Item.query.order_by(Item.date_reported.desc()).limit(9).all()

    lang = request.args.get("lang", "en")
    t = translations.get(lang, translations["en"])
    return render_template(
        "index.html",
        t=t,
        lang=lang,
        recent_items=recent_items
    )

# Admin routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Login Routes 
@routes.before_app_request
def refresh_unread_count():
    if 'user_id' in session:
        count = Message.query.filter_by(recipient_id=session['user_id'], read=False).count()
        session['unread_count'] = count


@routes.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session["user_id"] = user.user_id
            session["user_name"] = user.name
            session["is_admin"] = user.is_admin
            flash("Login successful!", "success")
            return redirect(url_for("routes.index"))
        flash("Invalid credentials", "danger")
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template("login.html", t=t, lang=lang, form=form)

@routes.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered.", "warning")
            return redirect(url_for("routes.login"))
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password_hash=generate_password_hash(form.password.data)
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("routes.login"))
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template("register.html", t=t, lang=lang, form=form)

@routes.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('routes.index'))

# Report Item Route
@routes.route("/report", methods=["GET", "POST"])
def report_item():
    if 'user_id' not in session:
        flash("You must be logged in to report an item.", "warning")
        return redirect(url_for('routes.login'))

    form = ItemForm()
    if form.validate_on_submit():
        new_item = Item(
            title=form.title.data,
            description=form.description.data,
            item_type=form.item_type.data,
            date_reported=form.date_reported.data,
            location=form.location.data,
            user_id=session.get("user_id")
        )
        db.session.add(new_item)
        db.session.commit()
        flash("Item reported successfully!", "success")
        return redirect(url_for("routes.view_items"))
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template("report.html", form=form, t=t, lang=lang)

# Lost/Found Items Route
@routes.route('/items')
def view_items():
    lost_items = Item.query.filter_by(item_type='lost').order_by(Item.date_reported.desc()).all()
    found_items = Item.query.filter_by(item_type='found').order_by(Item.date_reported.desc()).all()
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template('items.html', t=t, lang=lang, lost_items=lost_items, found_items=found_items)

# Admin Dashboard 
@routes.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    items = Item.query.all()
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template('admin.html', users=users, items=items, t=t, lang=lang)

@routes.route('/admin/toggle/<int:user_id>', methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash("Admin role updated.", "success")
    return redirect(url_for('routes.admin_dashboard'))

@routes.route('/admin/delete/<int:item_id>', methods=["POST"])
@admin_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted.", "info")
    return redirect(url_for('routes.admin_dashboard'))

@routes.route('/admin/edit/<int:item_id>', methods=["POST"])
@admin_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)

    item.title = request.form['title']
    item.item_type = request.form['item_type']
    item.location = request.form['location']
    item.description = request.form['description']

    db.session.commit()
    flash("Item updated successfully.", "success")
    return redirect(url_for("routes.admin_dashboard"))

@routes.route('/code-of-conduct')
def code_of_conduct():
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template('code_of_conduct.html', t=t, lang=lang)

translations = {
    'en': {
        'home': 'Home',
        'report_item': 'Report Item',
        'found_items': 'Found Items',
        'code_of_conduct': 'Code of Conduct',
        'welcome': 'Welcome',
        'all_rights': 'All rights reserved.',
        'chat_room': 'Chat Room',
        'lost_found': 'Your Campus Lost & Found Solution',
        'reunite': 'Help us reunite lost items with their owners on campus!',
        'recently_reported_item': 'Recently Reported Items',
        'find_it': 'About Find It',
        'find_it_description': 'Find It is a community-driven platform designed to help students and staff on campus reunite with their lost belongings.',
        'contact': 'Contact',
        'found_near': 'Found Near',
        'lost_near': 'Lost Near',
        'description_tr': 'Description',
        'date_tr': 'Date',
        'lost_tr': 'Lost',
        'found_tr': 'Found',
    },
    'es': {
        'home': 'Inicio',
        'report_item': 'Reportar objeto',
        'found_items': 'Objetos encontrados',
        'code_of_conduct': 'Código de conducta',
        'welcome': 'Bienvenido',
        'all_rights': 'Todos los derechos reservados.',
        'chat_room': 'Sala de Chat',
        'lost_found': 'Su solución para objetos perdidos en el campus',
        'reunite': '¡Ayúdanos a reunir artículos perdidos con sus dueños en el campus!',
        'recently_reported_item': 'Artículos peportados recientemente',
        'find_it': 'Acerca de Encuéntralo',
        'find_it_description': 'Encuéntralo es una plataforma comunitaria diseñada para ayudar a los estudiantes y al personal del campus a reencontrarse con sus pertenencias perdidas.',
        'contact': 'Contacto',
        'found_near': 'Encontrado cerca de',
        'lost_near': 'Perdido cerca de',
        'description_tr': 'Descripción',
        'date_tr': 'Fecha',
        'lost_tr': 'Perdido',
        'found_tr': 'Encontrado',
    }
}


# Direct messaging for users
@routes.route('/message/<int:user_id>', methods=['GET', 'POST'])
def message_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    recipient = User.query.get_or_404(user_id)
    sender_id = session['user_id']

    if request.method == 'POST':
        content = request.form['content']
        message = Message(sender_id=sender_id, recipient_id=recipient.user_id, content=content)
        db.session.add(message)
        db.session.commit()
        update_unread_count()  # Refresh unread counter after sending
        return redirect(url_for('routes.message_user', user_id=user_id))

    # Fetch message history
    messages = Message.query.filter(
        ((Message.sender_id == sender_id) & (Message.recipient_id == recipient.user_id)) |
        ((Message.sender_id == recipient.user_id) & (Message.recipient_id == sender_id))
    ).order_by(Message.timestamp).all()

    # Mark unread messages as read (those sent *to* current user)
    for msg in messages:
        if msg.recipient_id == sender_id and not msg.read:
            msg.read = True
    db.session.commit()

    update_unread_count()  # Refresh unread counter after reading

    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template('direct_message.html', recipient=recipient, messages=messages, t=t, lang=lang)

@routes.before_app_request
def update_unread_count():
    if 'user_id' in session:
        count = Message.query.filter_by(recipient_id=session['user_id'], read=False).count()
        session['unread_count'] = count



@socketio.on('private_message')
def handle_private_message(data):
    recipient_id = data['recipient_id']
    sender = data['sender']
    message = data['message']
    room = f"user_{recipient_id}"
    emit('private_message', {'sender': sender, 'message': message}, room=room)

@socketio.on('connect')
def on_connect():
    user_id = session.get('user_id')
    if user_id:
        join_room(f"user_{user_id}")

# Inbox Route for DM
@routes.route('/inbox')
def inbox():
    if 'user_id' not in session:
        return redirect(url_for('routes.login'))

    user_id = session['user_id']

    # Fetch all messages involving the current user
    messages = Message.query.filter(
        (Message.sender_id == user_id) | (Message.recipient_id == user_id)
    ).order_by(Message.timestamp.desc()).all()

    # Build conversations: {partner_id: last_message}
    conversations = {}
    for msg in messages:
        partner_id = msg.sender_id if msg.sender_id != user_id else msg.recipient_id
        if partner_id not in conversations:
            conversations[partner_id] = msg

    # Prepare conversation details
    partners = []
    for other_id, last_msg in conversations.items():
        user = User.query.get(other_id)

        # Count unread messages FROM this user TO current user
        has_unread = Message.query.filter_by(
            sender_id=other_id,
            recipient_id=user_id,
            read=False
        ).count() > 0

        partners.append({
            'user': user,
            'last_message': last_msg,
            'unread': has_unread,
            'last_sender_id': last_msg.sender_id if last_msg else None
        })

    # Store unread count in session for navbar
    unread_count = Message.query.filter_by(recipient_id=user_id, read=False).count()
    session['unread_count'] = unread_count

    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template('inbox.html', t=t, lang=lang, conversations=partners)



# Chatbot

@socketio.on('message')
def handle_chat_message(msg):
    msg_lower = msg.lower()
    keywords = re.findall(r'\w+', msg_lower)

    filters = [
        *(Item.title.ilike(f"%{word}%") for word in keywords),
        *(Item.description.ilike(f"%{word}%") for word in keywords),
        *(Item.location.ilike(f"%{word}%") for word in keywords)
    ]

    matching_items = Item.query.filter(
        or_(*filters)
    ).filter_by(item_type='found').all()

    if matching_items:
        results = [f"{item.title} – Found at {item.location}" for item in matching_items]
        reply = "Here’s what I found that might match:<br>" + "<br>".join(results)
    else:
        reply = "Sorry, I couldn’t find anything like that. You can report your lost item using the form."

    emit('message', {
        'user_msg': msg,
        'bot_reply': reply
    })



@routes.route('/chat')
def chat():
    if 'user_name' not in session:
        return redirect(url_for('routes.login'))
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template('chat.html', t=t, lang=lang, username=session['user_name'])


@socketio.on('message')
def handle_message(msg):
    username = session.get('user_name', 'Unknown')
    timestamp = datetime.now().strftime('%I:%M %p')  # e.g., "03:45 PM"
    full_msg = f"[{timestamp}] {username}: {msg}"
    emit('message', full_msg, broadcast=True)

@routes.route('/api/found-items')
def get_found_items():
    items = Item.query.all()
    results = [
        {
            "title": item.title.lower(),
            "description": item.description.lower(),
            "location": item.location.lower()
        }
        for item in items
    ]
    return jsonify(results)
