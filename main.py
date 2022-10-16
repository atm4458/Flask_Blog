from urllib import request
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

#Gravatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

@login_manager.user_loader
def user_loader(user_id):
    user = User.query.get(user_id)
    return user

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")
# db.create_all()

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key = True)
    account = db.Column(db.String(32), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="user")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key = True)
    comment = db.Column(db.String(500), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")

# admin_only Decorator
def admin_only(func):
    @wraps(func)
    def wrapper_func(*args, **kwargs):
        print(f"Check: {current_user}")
        if current_user.is_anonymous :
            print(kwargs)
            return redirect(url_for(login_manager.login_view, next=url_for(func.__name__, **kwargs)))
        elif current_user.is_active and current_user.id == 1:
            return func(*args, **kwargs)
        else:
            abort(403)
            return jsonify(error="No authorization"), 403
    return wrapper_func


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        is_email_exist = db.session.query(User.id).filter_by(email = request.form.get("email")).first()
        is_account_exist = db.session.query(User.id).filter_by(account = request.form.get("account")).first()
        if is_email_exist or is_account_exist:
            flash("Email or acconur name has been exist", "error")
            return render_template("register.html", form=form)

        hash_pass = generate_password_hash(request.form.get("password"), salt_length=8)
        user=User(
            account = request.form.get("account"),
            password = hash_pass,
            email=request.form.get("email")
        )
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()  
    if form.validate_on_submit():
        is_email_exist = db.session.query(User.id).filter_by(email = request.form.get("email")).scalar()
        if not is_email_exist:
            flash("Email is not exist.")
        
        else:
            user = User.query.get(is_email_exist)
            is_valid = check_password_hash(user.password, request.form.get("password"))
            if is_valid:
                login_user(user)

                next = request.args.get("next")
                print(next)
                

                return redirect(next or url_for("get_all_posts"))
            flash("Email is not exist.")

    return render_template("login.html", form = form)


@app.route('/logout')
def logout():
    if current_user.is_active:
        logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_anonymous:
            return redirect(url_for("login", next=url_for('show_post', post_id = post_id)))
        comment = Comment(
            comment = form.body.data,
            user_id=current_user.id,
            post_id=post_id
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))
    return render_template("post.html", post=requested_post, form = form)

@app.route("/create_db")
def create_db():
    db.create_all()
    return "Success"

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
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


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
