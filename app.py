from flask import Flask, render_template, redirect, flash, url_for, session
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField, FloatField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Length, Email, NumberRange
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_mail import Mail, Message
import uuid
import random
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = "hello1234"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Users.db'
app.config['SQLALCHEMY_BINDS'] = {
    "products": 'sqlite:///Products.db'
}
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'bigmovementoffical@gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'bigmovementoffical@gmail.com'
app.config['MAIL_PASSWORD'] = 'udru ljry bpwa jxtx'
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
app.config['UPLOAD_FOLDER'] = 'static'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, nullable=False, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(), nullable=False)
    date_joined = db.Column(db.DateTime, nullable=False,
                            default=datetime.utcnow())


class Products(db.Model):
    __bind_key__ = 'products'
    id = db.Column(db.Integer(), primary_key=True, nullable=True)
    product_name = db.Column(db.String(), nullable=False)
    product_slug = db.Column(db.String(), nullable=False)
    product_desc = db.Column(db.String(), nullable=False)
    product_price = db.Column(db.Integer(), nullable=False)
    product_image = db.Column(db.String()) 
    date_added = db.Column(db.DateTime(), nullable=False, default=datetime.utcnow())


with app.app_context():
    db.create_all()


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[
                       DataRequired(), Length(min=2, max=80)])
    username = StringField("Username", validators=[
                           DataRequired(), Length(min=2, max=80)])
    email = StringField("Email", validators=[
                        DataRequired(), Length(min=2, max=150)])
    password = PasswordField("Password", validators=[DataRequired()])
    confirm_password = PasswordField(
        "Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


class VerifyCodeForm(FlaskForm):
    code = IntegerField("Verification Code", validators=[
                        DataRequired(), NumberRange(min=100000, max=999999)])
    submit = SubmitField("Verify")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class AddProductForm(FlaskForm):
    product_name = StringField("Name", validators=[DataRequired()])
    product_slug = TextAreaField("Slug", validators=[DataRequired()])
    product_desc = TextAreaField("Description", validators=[DataRequired()])
    product_price = FloatField("Price", validators=[DataRequired()])
    product_image = FileField("Image", validators=[FileAllowed(['jpg', 'jpeg' , 'png'], DataRequired())])
    submit = SubmitField("Submit")


@app.route('/sign-up', methods=['POST', 'GET'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        session['name'] = form.name.data
        session['username'] = form.username.data
        session['email'] = form.email.data
        session['password'] = form.password.data
        username_query = Users.query.filter_by(
            username=form.username.data).first()
        email_query = Users.query.filter_by(email=form.email.data).first()
        if "@" not in form.email.data or ".com" not in form.email.data:
            flash("Enter A Valid Email Address!!!", 'error')
        elif not username_query:
            if not email_query:
                if form.password.data == form.confirm_password.data:
                    verification_code = ''.join(
                        [str(random.randint(0, 9)) for _ in range(6)])
                    msg = Message('Verification Code',
                                  recipients=[form.email.data])
                    msg.body = f'Your verification code is: {
                        verification_code}'
                    mail.send(msg)
                    session['verification_code'] = verification_code
                    flash("Verification code has been sent to your email.", 'success')
                    return redirect(url_for("verify_code"))
                else:
                    flash("Both passwords must match!!!", 'error')
            else:
                flash("Email Address is already in use!!!", 'error')
        else:
            flash("Username is already in use!!!", 'error')
    return render_template("register.html", form=form)

@app.route('/verify-code', methods=['POST', 'GET'])
def verify_code():
    form = VerifyCodeForm()
    if form.validate_on_submit():
        email = session.get('email')
        verification_code = session.get('verification_code')
        if email and verification_code and email == session['email'] and str(form.code.data) == session['verification_code']:
            new_user = Users(name=session['name'], username=session['username'],
                             email=session['email'], password=generate_password_hash(session['password']), date_joined=datetime.utcnow())
            db.session.add(new_user)
            db.session.commit()
            flash("Verification successful! You can now log in.", 'success')
            session.pop('name', None)
            session.pop('username', None)
            session.pop('email', None)
            session.pop('password', None)
            session.pop('verification_code', None)
            return redirect(url_for("login"))
        else:
            flash("Invalid verification code. Please try again.", 'error')
    return render_template("verify-code.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", 'success')
    return redirect(url_for("signup"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                if user.email:
                    login_user(user)
                    flash("Login successful!", 'success')
                    return redirect(url_for("profile"))
                else:
                    flash("Wrong Email Adress!!!")
            else:
                flash("Wrong Password Or Usename!!!")
        else:
            flash("Wrong Password Or Username!!!")
    return render_template("login.html", form=form)


@app.route('/profile')
@login_required
def profile():
    return render_template("profile.html", user=current_user)


@app.route('/profile/delete/<int:id>' , methods=['POST' , 'GET'])
def DeleteUser(id):
    user = Users.query.get_or_404(id)
    if user.id == current_user.id:
        try:
            db.session.delete(user)
            db.session.commit()
            flash("Account Deleted!!!")
            return redirect(url_for("signup"))
        except Exception as e:
            flash(f"An Error Occurred: {str(e)}")
    return render_template("profile.html", user=current_user)

@app.route('/', methods=['POST', 'GET'])
def products():
    products = Products.query.order_by(desc(Products.date_added)).all()
    return render_template("products.html", products=products)

@app.route('/product/<int:id>' , methods=['POST' , 'GET'])
def product(id):
    product = Products.query.get_or_404(id)
    return render_template('product.html' , product=product)

@app.route('/add-products', methods=['POST', 'GET'])
@login_required
def AddProducts():
    form = AddProductForm()
    if current_user.id == 1 and current_user.username == "Admin":
        if form.validate_on_submit():
            if form.product_image.data:
                image_file = form.product_image.data
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], str(uuid.uuid4()) + filename).replace('\\', '/')
                image_file.save(image_path)
                image_path_db = image_path.replace('static/', '')
            new_product = Products(
                product_name=form.product_name.data,
                product_slug=form.product_slug.data,
                product_desc=form.product_desc.data,
                product_price=form.product_price.data,
                product_image=image_path_db,  
                date_added=datetime.utcnow()
            )
            db.session.add(new_product)
            db.session.commit()
            flash("Product Added Successfully!!!")
            return redirect(url_for("products"))
    else:
        flash("You aren't authorized to access this page!!!")
        return redirect(url_for("products"))
    return render_template("add_products.html", form=form)


@app.route('/products/delete/<int:id>' , methods=['POST' , 'GET'])
@login_required
def DeleteProduct(id):
    delete_product = Products.query.get_or_404(id)
    if current_user.id == 1 and current_user.username == "Admin":
        try:
            if delete_product.product_image:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], delete_product.product_image)
                if os.path.exists(image_path):
                    os.remove(image_path)
            db.session.delete(delete_product)
            db.session.commit()
            flash("Deleted Product Successfully!!!")
            return redirect(url_for("products"))
        except Exception as e:
            flash(f"An Error Occurred: {str(e)}")
    return redirect(url_for("products"))

@app.route('/products/edit/<int:id>' , methods=['POST' , 'GET'])
@login_required
def EditProduct(id):
    edit_product = Products.query.get_or_404(id)
    form = AddProductForm()
    if current_user.id == 1 and current_user.username == "Admin":
        if form.validate_on_submit():
            edit_product.product_name = form.product_name.data
            edit_product.product_slug = form.product_slug.data
            edit_product.product_desc = form.product_desc.data
            edit_product.product_price = form.product_price.data
            if form.product_image.data:
                if edit_product.product_image:
                    prev_image_path = os.path.join(app.config['UPLOAD_FOLDER'], edit_product.product_image)
                    if os.path.exists(prev_image_path):
                        os.remove(prev_image_path)
                image_file = form.product_image.data
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], str(uuid.uuid4()) + filename).replace('\\', '/')
                image_file.save(image_path)
                edit_product.product_image = image_path.replace('static/', '')
            db.session.add(edit_product)
            db.session.commit()
            flash("Product Edited!!!")
            return redirect(url_for("product", id=id))
        form.product_name.data = edit_product.product_name
        form.product_slug.data = edit_product.product_slug
        form.product_desc.data = edit_product.product_desc
        form.product_price.data = edit_product.product_price
    return render_template("edit_product.html" , form=form)

 
if __name__ == "__main__":
    app.run(debug=True, port=5500)