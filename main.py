from flask import Flask, render_template, redirect, request, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import os
import stripe

cart = []

#new_user = User(email=email, username=username, password=generate_password_hash(password, method='sha256'),
def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.get_id():
            if current_user.get_id() == "1":
                return func(*args, **kwargs)
            else:
                return "<h1>Forbidden</h1>" \
                       "<p> you do not have access to this page </p>"
        else:
            return "<h1>Forbidden</h1>" \
                   "<p> you do not have access to this page </p>"

    return wrapper

stripe_keys = {
    "secret_key": os.environ["STRIPE_SECRET_KEY"],
    "publishable_key": os.environ["STRIPE_PUBLISHABLE_KEY"],
}

stripe.api_key = stripe_keys['secret_key']

app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), unique=True, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prod_name = db.Column(db.String(1000), nullable=False)
    prod_price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(1000), nullable=False)
    price_id = db.Column(db.String(1000), unique=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method =='POST':
        cart = []
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()


        if user:
            print('got here')
            access_granted = check_password_hash(user.password, password)
            if access_granted:
                login_user(user)
                cart = []
                return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        cart=[]
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        user = User(name=name, email=email, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        cart = []
        return redirect(url_for('home'))

    return render_template('register.html')
@login_required
@app.route('/logout')
def logout():
    logout_user()

    return redirect(url_for('home'))

@login_required
@app.route('/add', methods=['POST', 'GET'])
def add_product():
    if request.method == 'POST':
        product_name = request.form.get('product_name')
        product_price = request.form.get('product_price')
        image_url = request.form.get('img_url')
        price_id = request.form.get('product_id')

        new_product = Product(prod_name=product_name, prod_price=product_price, image_url=image_url, price_id=price_id)
        db.session.add(new_product)
        db.session.commit()

        return redirect(url_for('manage_products'))


    return render_template('add.html')

@login_required
@app.route('/products')
def manage_products():
    products = Product.query.all()
    print(products)

    return render_template('ProductManagement.html', products=products)



@app.route('/management')
@admin_only
def manage():
    all_users = User.query.all()

    return render_template('management.html', users=all_users)

@app.route('/delete_user/<user_id>', methods=['DELETE', 'GET'])
@admin_only
def delete_user(user_id):
    deleted_user = User.query.filter_by(id=user_id).first()
    db.session.delete(deleted_user)
    db.session.commit()

    return redirect(url_for('manage'))

@app.route('/product/<prod_id>')
def product(prod_id):
    current_product = Product.query.filter_by(id=prod_id).first()

    return render_template('product_page.html', product=current_product)

@app.route('/add_to_cart/<product_id>')
def add_to_cart(product_id):
    product = Product.query.filter_by(id=product_id).first()
    cart.append(product)

    return redirect(url_for('home'))

@app.route('/my_cart')
def show_cart():
    total = 0
    for item in cart:
        total += item.prod_price
    return render_template('cart.html', cart=cart, total=total)

@app.route('/checkout', methods=['GET'])
def buy_now():
    stripe_param = [{'price': item.price_id, 'quantity': 1} for item in cart]
    session = stripe.checkout.Session.create(
        success_url=url_for('success', _external=True),
        line_items=stripe_param,
        mode="payment",
        cancel_url=url_for('home', _external=True),
    )
    return redirect(session.url)

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/delete/<product_id>')
def delete_product(product_id):
    product = Product.query.filter_by(id=product_id).first()
    db.session.delete(product)
    db.session.commit()

    return redirect(url_for('manage_products'))




with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)  # Start the Flask development server