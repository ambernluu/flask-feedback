from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import UserForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import Unauthorized

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///feedback_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abchjgu123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)


@app.route('/')
def home_page():
    if 'username' not in session:
        return redirect('/login')
    else:
         return redirect(f"/users/{session['username']}")

                    ################## 
                        # USERS #
                    ##################

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        new_user = User.register(username, password, email, first_name, last_name)

        db.session.add(new_user)
        try:
            db.session.commit()
        except IntegrityError:
            form.username.errors.append('Username taken.  Please pick another')
            return render_template('register.html', form=form)
        session['username'] = new_user.username
        flash('Welcome! Successfully Created Your Account!', "success")
        return redirect(f"/users/{new_user.username}")

    return render_template('users/register.html', form=form)

@app.route('/users/<username>')
def user_page(username):
    if 'username' not in session:
        flash("You must be logged in to view!", "danger")
        return redirect('/login')
    user = User.query.get(username)
    return render_template('/users/user_info.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login_user():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)
        if user:
            flash(f"Welcome Back, {user.username}!", "primary")
            session['username'] = user.username
            return redirect(f"/users/{user.username}")
        else:
            form.username.errors = ['Invalid username/password.']

    return render_template('/users/login.html', form=form)

@app.route('/logout')
def logout_user():
    session.pop('username')
    flash("Goodbye!", "info")
    return redirect('/')

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    user = User.query.get_or_404(username)

    db.session.delete(user)
    db.session.commit()
    session.pop('username')
    flash(f"Username: {user.username} Has Been Deleted!", "success")
    return redirect('/')


                    ################## 
                       # FEEDBACK #
                    ##################

@app.route("/users/<username>/feedback/new", methods=["GET", "POST"])
def new_feedback(username):

    if "username" not in session or username != session['username']:
        raise Unauthorized()

    form = FeedbackForm()

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        feedback = Feedback(
            title=title,
            content=content,
            username=username,
        )

        db.session.add(feedback)
        db.session.commit()

        return redirect(f"/users/{feedback.username}")

    else:
        return render_template("feedback/new.html", form=form)

@app.route("/feedback/<int:id>/update", methods=["GET", "POST"])
def edit_feedback(id):
    feedback = Feedback.query.get(id)
    if "username" not in session or feedback.username != session['username']:
        raise Unauthorized()

    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()

        return redirect(f"/users/{feedback.username}")

    else:
        return render_template("feedback/edit.html", form=form)

@app.route("/feedback/<int:id>/delete", methods=["POST"])
def delete_feedback(id):
    feedback = Feedback.query.get(id)
    if "username" not in session or feedback.username != session['username']:
        raise Unauthorized()

    db.session.delete(feedback)
    db.session.commit()

    flash(f"Feedback for {feedback.title} Has Been Deleted!", "success")
    return redirect(f"/users/{feedback.username}")