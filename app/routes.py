from flask import Blueprint, render_template, redirect, url_for, flash, session, request, abort
from .forms import LoginForm, RegisterForm, ItemForm
from .models import db, User, Item
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from app import socketio
from flask_socketio import emit

routes = Blueprint("routes", __name__)

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

# Routes 
@routes.route("/")
def index():
    return render_template("index.html")

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
    return render_template("login.html", form=form)

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
    return render_template("register.html", form=form)

@routes.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('routes.index'))

@routes.route("/report", methods=["GET", "POST"])
def report_item():
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
    return render_template("report.html", form=form)

@routes.route('/items')
def view_items():
    lost_items = Item.query.filter_by(item_type='lost').order_by(Item.date_reported.desc()).all()
    found_items = Item.query.filter_by(item_type='found').order_by(Item.date_reported.desc()).all()
    return render_template('items.html', lost_items=lost_items, found_items=found_items)

# Admin Dashboard 
@routes.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()
    items = Item.query.all()
    return render_template('admin.html', users=users, items=items)

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
    return render_template('code_of_conduct.html')

from flask import render_template, request

translations = {
    'en': {
        'home': 'Home',
        'report_item': 'Report Item',
        'found_items': 'Found Items',
        'code_of_conduct': 'Code of Conduct',
        'welcome': 'Welcome',
        'all_rights': 'All rights reserved.'
    },
    'es': {
        'home': 'Inicio',
        'report_item': 'Reportar objeto',
        'found_items': 'Objetos encontrados',
        'code_of_conduct': 'Código de conducta',
        'welcome': 'Bienvenido',
        'all_rights': 'Todos los derechos reservados.'
    }
}

@app.route('/')
def index():
    lang = request.args.get('lang', 'en')
    t = translations.get(lang, translations['en'])
    return render_template('index.html', t=t, lang=lang)

@routes.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('routes.login'))
    return render_template('chat.html', username=session['username'])


@socketio.on('message')
def handle_message(msg):
    username = session.get('userrname', 'Unknown')
    full_msg = f"{username}: {msg}"
    emit('message', full_msg, broadcast=True)