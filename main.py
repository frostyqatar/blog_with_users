from functools import wraps

import flask
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, CommentForm
from flask_gravatar import Gravatar
import os
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(
    app,
    size=100,
    rating = 'g',
    default = 'retro'


)
#login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
# app.config['SQLALCHEMY_BINDS'] = {"two": 'sqlite:///users.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "blog_users"
    # __bind_key__ = "two"
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    username = db.Column(db.String(250), nullable=False)
    comment = relationship("Comment", back_populates="author")
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates = "author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'))
    author = relationship("User", back_populates = "posts")
    comments = relationship("Comment", back_populates = "parent_post")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key = True)
    author_id = db.Column(db.Integer, db.ForeignKey('blog_users.id'))
    comment = db.Column(db.String(250))
    author = relationship("User", back_populates = "comment")
    #posts
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates ="comments")

# db.create_all()
# db.create_all(bind=["two"])
class registerForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    username = StringField(label='Username', validators=[DataRequired()])
    submit = SubmitField(label="REGISTER!")
class loginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="Submit")

# print(db.session.query(User).all())

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods = ["POST", "GET"])
def register():
    registered_user = registerForm()
    print(db.session.query(User).filter_by(email=registered_user.email.data))
    if registered_user.validate_on_submit():
        if registered_user.email.data not in db.session.query(User).filter_by(email=registered_user.email.data):
            add_user_to_db = User(
                username = registered_user.username.data,
                password =
                generate_password_hash(
                    registered_user.password.data,
                    method="pbkdf2:sha256",
                    salt_length=8
                )
                ,
                email = registered_user.email.data

            )
            db.session.add(add_user_to_db)
            db.session.commit()
            query_user_for_login = db.session.query(User).filter_by(email=registered_user.email.data).first()
            login_user(query_user_for_login)
            return redirect(url_for('get_all_posts'))
        else:
            flask.flash("WTF IS WRONG WITH YOU!! YOU ARE ALREADY REGISTERED. JUST LOG IN. HERE:")
            return redirect(url_for('login'))


    return render_template("register.html", form = registered_user)


@app.route('/login', methods = ["GET", "POST"])
def login():
    loginform = loginForm()
    if loginform.validate_on_submit():
        user_email = loginform.email.data
        user_from_db = db.session.query(User).filter_by(email = user_email).first()
        print(user_from_db.password)

        if user_from_db:
            print("I got here")
            if check_password_hash(user_from_db.password, loginform.password.data):

                login_user(user_from_db)

                return redirect(url_for("get_all_posts"))
            else:
                flask.flash("WHAT THE HELL WERE THOSE CREDENTIALS YOU HACKER!!!!!!!!")
                return render_template("login.html", form=loginform)
        else:
            flask.flash("WHAT THE HELL WERE THOSE CREDENTIALS YOU HACKER!!!!!!!!")
            return render_template("login.html", form = loginform)



    return render_template("login.html", form = loginform)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    comments = db.session.query(Comment).filter_by(post_id = post_id).all()
    print(comments)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flask.flash("You need to sign in first, dude.")
            return redirect(url_for('login'))
        else:
            print(comment_form.body)
            comment_user = Comment(

                author_id=current_user.id,
                comment = comment_form.body.data,
                post_id = post_id
            )
            db.session.add(comment_user)
            db.session.commit()
            comments = db.session.query(Comment).filter_by(post_id = post_id).all()
            print(comments)
            return redirect(url_for('show_post',  post_id = post_id))

    return render_template("post.html", post=requested_post, form = comment_form, comments = comments)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        try:
            if current_user.id != 1 or not current_user.is_active:
                return abort(403)
        #Otherwise continue with the route function
        except AttributeError:
            return abort(403)
        else:
            return f(*args, **kwargs)
    return decorated_function




@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id = current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))
##### TESTING AREA
# print(db.session.query(Comment).all())
# print(db.session.query(User).all())

if __name__ == "__main__":
    app.run(host='localhost', port=5000, debug=True)
