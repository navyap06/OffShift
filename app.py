from flask import Flask, render_template, redirect, url_for, flash, request,session 
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager,UserMixin, login_user, login_required, logout_user, current_user
import os


users = []

app = Flask(__name__)
app.secret_key = 'your_secret_key'

basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "your_secret_key_here"


db = SQLAlchemy(app)
login_manager=LoginManager(app)
login_manager.init_app(app)
login_manager.login_view='login'


class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_name = db.Column(db.String(100), nullable=False)
    leave_type = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.String(10), nullable=False)
    end_date = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default="Pending")


class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
        


with app.app_context():
    db.create_all()

ADMIN_EMAIL = "admin@gmail.com"
ADMIN_PASSWORD = "admin123"


@app.route('/')
def start():
    return render_template("start.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")
        role = request.form.get("role")

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("register"))

        # Check if email is already registered
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return redirect(url_for("register"))

        # Create a new user and hash the password
        new_user = User(name=name, email=email, mobile=mobile, role=role)
        new_user.set_password(password)  # Hash the password properly

        # Add user to database
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))  # Redirect to login page

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            # flash("Welcome, Admin!", "success")
            return redirect(url_for("admin"))  

        else:
            
            user = User.query.filter_by(email=email).first()
            if user and user.check_password(password):  
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for("index"))  
            else:
                flash("Invalid credentials!", "danger")

    return render_template("login.html")


@app.route('/index')
@login_required
def index():
    user=current_user
    if current_user.role == 'admin':
        leave_requests = LeaveRequest.query.all()
        return render_template('admin.html', leave_requests=leave_requests)
    else:
        leave_requests = LeaveRequest.query.filter_by(id=current_user.id).all()
        return render_template('index.html', leave_requests=leave_requests,user=user)


# Admin Dashboard
@app.route('/admin')
def admin():
    user = current_user
    return render_template("admin.html",user=user) 

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))



@app.route('/leave')
def leave():
    # if 'user_id' not in session:
    #     return redirect(url_for('login'))
    leave_requests = LeaveRequest.query.all()
    return render_template('leave.html', leave_requests=leave_requests)

@app.route('/leave1')
def leave1():
    # if 'user_id' not in session:
    #     return redirect(url_for('login'))
    leave_requests = LeaveRequest.query.all()
    return render_template('leave1.html', leave_requests=leave_requests)


@app.route('/apply', methods=['GET', 'POST'])
def apply_leave():
    # if 'user_id' not in session:
    #     return redirect(url_for('login'))
    if request.method == 'POST':
        employee_name = request.form['employee_name']
        leave_type = request.form['leave_type']
        start_date = request.form['start_date']
        end_date = request.form['end_date']

        new_leave = LeaveRequest(employee_name=employee_name, leave_type=leave_type,
                                 start_date=start_date, end_date=end_date)
        db.session.add(new_leave)
        db.session.commit()
        return redirect(url_for('leave1'))  

    return render_template('apply_leave.html')


@app.route('/update_status/<int:id>', methods=['POST'])
def update_status(id):
    # if 'user_id' not in session:
    #     return redirect(url_for('leave'))
    leave_request = LeaveRequest.query.get_or_404(id)
    action = request.form['action']
    if action == 'approve':
        leave_request.status = 'Approved'
    elif action == 'reject':
        leave_request.status = 'Rejected'
    elif action == 'delete':
        db.session.delete(leave_request)
    db.session.commit()
    return redirect(url_for('leave')) 




@app.route('/clear', methods=['POST'])
def clear():
    # if 'user_id' not in session:
    #     return redirect(url_for('leave'))
    db.session.query(LeaveRequest).delete()
    db.session.commit()
    return redirect(url_for('leave'))


@app.route('/clear1', methods=['POST'])
def clear1():
    # if 'user_id' not in session:
    #     return redirect(url_for('leave1'))
    db.session.query(LeaveRequest).delete()
    db.session.commit()
    return redirect(url_for('leave1'))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Handle the form submission here
        email = request.form.get('email')
        if email:
            # Here, you could add logic to send a password reset link to the email
            print(f"Password reset request for email: {email}")
            return redirect(url_for('password_reset_success'))
    return render_template('forgot.html')


# Route for a success page after form submission
@app.route('/reset-success')
def password_reset_success():
    return render_template('reset.html')

@app.route('/base')
def base():
    return render_template("base.html")

@app.route('/profile')
@login_required
def profile():
    user = current_user
    return render_template("profile.html", user=user)

@app.route('/workers')
def workers():
    return render_template("workers.html")

@app.route('/AboutUs')
def AboutUs():
    return render_template("aboutUs.html")

@app.route('/policy')
def policy():
    return render_template("policy.html")


if __name__ == '__main__':
    app.run(debug=True,port=3444)
