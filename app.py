from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import relationship


app = Flask(__name__)

app.config['SECRET_KEY'] = 'P*Rq#%9&vv3EM$VsBq^:<w@1fk,8W2,FuXr^b4i#RAdP+jz|^^,V8,h.q=-f[{MM'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
db = SQLAlchemy(app)

bcrypt = Bcrypt()

app.app_context().push()

login_manager = LoginManager(app)
login_manager.login_view = 'login'


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = relationship('User', back_populates='notes')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/notes')
@login_required
def index():
    """
    Отображает главную страницу со списком всех заметок
    """
    notes = Note.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', notes=notes)


@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    """
    Добавляет новую заметку и перенаправляет на главную страницу
    """
    content = request.form['content']
    new_note = Note(content=content, user_id=current_user.id) 
    db.session.add(new_note)
    db.session.commit()
    return redirect('/notes')


@app.route('/note/<int:note_id>')
@login_required
def view_note_detail(note_id):
    """
    Отображает детали заметки или ошибку 404, если заметка не найдена
    """
    note = Note.query.get(note_id)

    if not note:
        return render_template('404.html', note=note)

    return render_template('note.html', note=note)


@app.route('/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    """
    Редактирует заметку по её идентификатору
    """
    note = Note.query.get(note_id)

    if note.user_id != current_user.id:
        return render_template('404.html', note=note)
    
    if request.method == 'POST':
        note.content = request.form['content']
        db.session.commit()
        return redirect('/notes')

    return render_template('edit_note.html', note=note)


@app.route('/delete/<int:note_id>', methods=['GET', 'POST'])
@login_required
def delete_note(note_id):
    """
    Удаляет заметку по её идентификатору
    """
    note = Note.query.get(note_id)
    if note.user_id != current_user.id:
        return render_template('404.html', note=note)
    if request.method == 'POST':
        db.session.delete(note)
        db.session.commit()
        return redirect('/notes')

    return render_template('delete_note.html', note=note)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html')


@app.route('/', methods=['GET', 'POST'])
def register():
    """
    Обрабатывает регистрацию новых пользователей
    """
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Обработка страницы входа пользователя
    """
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0' port=5000)