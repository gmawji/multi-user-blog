import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import random
import codecs
import time

from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

secret = 'aa7b4911c552e3792efe9eea514f1d8d'

# Global
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Get post key
def post_key(name='default'):
    return db.Key.from_path('Blog', name)

# Make secure cookie value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Check secure cookie value
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Make salt!
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Create password with hash name, password, & salt
def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(''.join([name, pw, salt])).hexdigest()
    return '%s,%s' % (salt, h)

# Check if password is valid by comparing hash value
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# Get user key
def users_key(group='default'):
    return db.Key.from_path('users', group)

# Define username
USER_RE = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')

# Validate username
def valid_username(username):
    return username and USER_RE.match(username)

# Define password
PASS_RE = re.compile(r'^.{3,20}$')

# Validate password
def valid_password(password):
    return password and PASS_RE.match(password)

# Define email
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

# Validate password
def valid_email(email):
    return not email or EMAIL_RE.match(email)


# Handler

class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Set secure cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))


    # Read secure cookie
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Set cookie for log in
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Reset cookie for log out
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Get user from secure cookie
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

# User


# Create user info database
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # Get user by user ID
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    # Get user by name
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # Hash user password
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    # Check valid login passwords
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Posts


# Create post posts database
class Blog(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    user = db.ReferenceProperty(User,
                                required=True,
                                collection_name="posts")

    # Display line breaks when content is rendered
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", post=self)

# Likes


# Create database for likes
class Like(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    # Get number of likes for post
    @classmethod
    def by_blog_id(cls, blog_id):
        l = Like.all().filter('post =', blog_id)
        return l.count()

    # Get number of likes for post and user
    @classmethod
    def check_like(cls, blog_id, user_id):
        cl = Like.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cl.count()


# Unlikes

# Create database for unlikes
class Unlike(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)

    # Get number of unlikes for post
    @classmethod
    def by_blog_id(cls, blog_id):
        ul = Unlike.all().filter('post =', blog_id)
        return ul.count()

    # Get number of likes for post and user
    @classmethod
    def check_unlike(cls, blog_id, user_id):
        cul = Unlike.all().filter(
            'post =', blog_id).filter(
            'user =', user_id)
        return cul.count()

# Comments


# Create a database for comments
class Comment(db.Model):
    post = db.ReferenceProperty(Blog, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)

    # Get number of comments
    @classmethod
    def count_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id)
        return c.count()

    # Get comments
    @classmethod
    def all_by_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id).order('created')
        return c

# Main Page


class BlogPage(BlogHandler):

    def get(self):
        # Get all post posts with GQL Query
        posts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC")
        if posts:
            self.render("index.html", posts=posts)

# New Post


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    # Get content of user and create new post
    def post(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

        subject = self.request.get("subject")
        content = self.request.get("content").replace('\n', '<br>')
        user_id = User.by_name(self.user.name)

        # If subject and content exist then redirect us
        # to the post page.
        if subject and content:
            a = Blog(
                parent=post_key(),
                subject=subject,
                content=content,
                user=user_id)
            a.put()
            self.redirect('/post/%s' % str(a.key().id()))
        # If no subject or content then send post_error
        else:
            post_error = "You need a subject and some content to submit a post."
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                post_error=post_error)

#Post Page


class PostPage(BlogHandler):

    # Get key for post post
    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=post_key())
        post = db.get(key)

        # If no key returns send error 404
        if not post:
            self.error(404)
            return
        # Fetches likes, unlikes, post comments, & comment count
        # for the post fetched post
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        pcomments = Comment.all_by_blog_id(post)
        comcount = Comment.count_by_blog_id(post)

        # Renders our content
        self.render(
            "post.html",
            post=post,
            likes=likes,
            unlikes=unlikes,
            pcomments=pcomments,
            comcount=comcount)

    def post(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=post_key())
        post = db.get(key)
        user_id = User.by_name(self.user.name)
        comcount = Comment.count_by_blog_id(post)
        pcomments = Comment.all_by_blog_id(post)
        likes = Like.by_blog_id(post)
        unlikes = Unlike.by_blog_id(post)
        previously_liked = Like.check_like(post, user_id)
        previously_unliked = Unlike.check_unlike(post, user_id)

        # Check if user is logged in
        if self.user:
            # If logged user clicks on like
            if self.request.get("like"):
                # Check to see if liking user own post
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    # Check if user has liked post before
                    if previously_liked == 0:
                        # Add likes to the database and refresh
                        l = Like(
                            post=post, user=User.by_name(
                                self.user.name))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    # If user has liked before send error
                    else:
                        error = "You already liked this post!"
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comcount=comcount,
                            pcomments=pcomments)
                # If user is trying to like own post send error
                else:
                    error = "You can't like your own post."
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comcount=comcount,
                        pcomments=pcomments)
            # If logged in user clicks unlike
            if self.request.get("unlike"):
                # Check to see if unliking user own post
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    # Check if user has unliked post before
                    if previously_unliked == 0:
                        # Add ulikes to the database and refresh
                        ul = Unlike(
                            post=post, user=User.by_name(
                                self.user.name))
                        ul.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    #If user has unliked before send error
                    else:
                        error = "You already unliked this post."
                        self.render(
                            "post.html",
                            post=post,
                            likes=likes,
                            unlikes=unlikes,
                            error=error,
                            comcount=comcount,
                            pcomments=pcomments)
                # If user is trying to unlike own post send error
                else:
                    error = "You can't unlike your own post."
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        error=error,
                        comcount=comcount,
                        pcomments=pcomments)
            # If logged in user clicks on add comment
            # Get comment text
            if self.request.get("add_comment"):
                comment_text = self.request.get("comment_text")
                # Check if comment text has been entered
                if comment_text:
                    # Add entered text to db
                    c = Comment(
                        post=post, user=User.by_name(
                            self.user.name), text=comment_text)
                    c.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                # If nothing has been entered send error
                else:
                    comment_error = "You must enter a comment before you click Post."
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comcount=comcount,
                        pcomments=pcomments,
                        comment_error=comment_error)
            # If logged in user clicks edit
            if self.request.get("edit"):
                # Check if logged in user created post
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    # If yes take user to edit page
                    self.redirect('/edit/%s' % str(post.key().id()))
                # If post does not belong to user send error
                else:
                    error = "You can't edit another user's post."
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comcount=comcount,
                        pcomments=pcomments,
                        error=error)
            # If logged in user clicks on delete
            if self.request.get("delete"):
                # Check if logged in user created post
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    # If yes delete post
                    db.delete(key)
                    time.sleep(0.1)
                    self.redirect('/')
                # If post does not belong to user send error
                else:
                    error = "You can't delete another user's post."
                    self.render(
                        "post.html",
                        post=post,
                        likes=likes,
                        unlikes=unlikes,
                        comcount=comcount,
                        pcomments=pcomments,
                        error=error)
        # If user is not logged in
        # Redirect to login page
        else:
            self.redirect("/login")

# Delete Comment


class DelComment(BlogHandler):

    def get(self, blog_id, comment_id):
        # Get comment
        comment = Comment.get_by_id(int(comment_id))
        # Check comment
        if comment:
            # Check if user is creator of comment
            if comment.user.name == self.user.name:
                # If user is creator
                # Delete comment
                db.delete(comment)
                time.sleep(0.1)
                self.redirect('/post/%s' % str(blog_id))
            # If user is not creator send error
            else:
                self.write("You can't delete another user's comment.")
        # If no comment
        else:
            self.write("Oops. This comment vanished.")

# Edit Comment


class EComment(BlogHandler):

    def get(self, blog_id, comment_id):
        # Get the comment
        post = Blog.get_by_id(int(blog_id), parent=post_key())
        comment = Comment.get_by_id(int(comment_id))
        # Check comment
        if comment:
            # Check if user is creator of comment
            if comment.user.name == self.user.name:
                # If user is creator
                # Edit comment
                self.render("ecomment.html", comment_text=comment.text)
            # If user is not creator send error
            else:
                error = "You can't edit another user's comment."
                self.render("ecomment.html", edit_error=error)
        # If no comment
        else:
            error = "Oops. This comment vanished."
            self.render("ecomment.html", edit_error=error)

    def post(self, blog_id, comment_id):
        # If user clicks on update comment
        if self.request.get("update_comment"):
            # Get the comment
            comment = Comment.get_by_id(int(comment_id))
            # Check if user is creator of comment
            if comment.user.name == self.user.name:
                # If user is creator
                # Update comment
                comment.text = self.request.get('comment_text')
                comment.put()
                time.sleep(0.1)
                self.redirect('/post/%s' % str(blog_id))
            # If user is not creator send error
            else:
                error = "You can't edit another user's comment.'"
                self.render(
                    "ecomment.html",
                    comment_text=comment.text,
                    edit_error=error)
        # If user clicks cancel
        # Redirect to post page
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(blog_id))

# Edit Post


class EditPost(BlogHandler):

    def get(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=post_key())
        post = db.get(key)

        if self.user:
            # Check is user is creator of post
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                # If user is creator
                # Load editpost page
                self.render("editpost.html", post=post)
            # If user is not creater
            # Send message
            else:
                self.response.out.write("You can't edit another user's post.")
        # If user is not logged in
        # Redirect to login page
        else:
            self.redirect("/login")

    def post(self, blog_id):
        key = db.Key.from_path("Blog", int(blog_id), parent=post_key())
        post = db.get(key)

        # If user clicks on update
        if self.request.get("update"):

            # Get content when form is being submitted
            subject = self.request.get("subject")
            content = self.request.get("content").replace('\n', '<br>')

            # Check if user is author
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                # Check if both fields are popluated
                if subject and content:
                    # Update the post
                    post.subject = subject
                    post.content = content
                    post.put()
                    time.sleep(0.1)
                    # Redirct to post page
                    self.redirect('/post/%s' % str(post.key().id()))
                # If subject or content or both is missing
                # Send post_error
                else:
                    post_error = "You must enter a subject and some content."
                    self.render(
                        "editpost.html",
                        subject=subject,
                        content=content,
                        post_error=post_error)
            # If user is not creator send message
            else:
                self.response.out.write("You can't edit another user's post.")
        # If user clicks cancel
        # Redirect back to post page
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post.key().id()))

# Signup


class Signup(BlogHandler):

    def get(self):
        self.render("signup-frm.html")

    def post(self):
        have_error = False
        # Get user info
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        # If there is an error
        # Show page with error and keep values
        if have_error:
            self.render("signup-frm.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# Register


class Register(Signup):

    def done(self):
        # Check username uniqueness
        u = User.by_name(self.username)
        # If username not unique
        # Send error
        if u:
            error = 'That username already exists. Please choose another one.'
            self.render('signup-frm.html', error_username=error)
        # If username doesn't exist add user and send to welcome page
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

# Welcome


class Welcome(BlogHandler):

    def get(self):
        # Check if user is signed up
        if self.user:
            # Show welcome message
            self.render("welcome.html", username=self.user.name)
        # If not signed up send to signup page
        else:
            self.redirect("/signup")

# Return Welcome


class ReturnWelcome(BlogHandler):

    def get(self):
        # Check if user is logged in
        if self.user:
            # Show welcome message
            self.render("rwelcome.html", username=self.user.name)
        # If not logged in send to login page
        else:
            self.redirect("/login")

# Login


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        # Get username
        username = self.request.get('username')
        # Get password
        password = self.request.get('password')

        # Get user account for username & password
        u = User.login(username, password)

        # If account exists
        if u:
            # Login and send to welcome page
            self.login(u)
            self.redirect('/rwelcome')
        # If login does not exist
        # Send error
        else:
            error = 'Hmmm. Something went wrong there. That login is Invalid.'
            self.render('login-form.html', error=error)

# Logout


class Logout(BlogHandler):

    def get(self):
        # Check if user is logged in
        if self.user:
            # Logout user and send to login page
            self.logout()
            self.redirect("/login")
        # If user is not logged in, logout shouldn't show
        # If it shows send error
        else:
            error = 'Please log in before your try to log out.'
            self.render('login-form.html', error=error)

#====================================================

app = webapp2.WSGIApplication([
    ('/', BlogPage),
    ('/newpost', NewPost),
    ('/post/([0-9]+)', PostPage),
    ('/login', Login),
    ('/logout', Logout),
    ('/signup', Register),
    ('/welcome', Welcome),
    ('/rwelcome', ReturnWelcome),
    ('/edit/([0-9]+)', EditPost),
    ('/post/([0-9]+)/editcomment/([0-9]+)', EComment),
    ('/post/([0-9]+)/deletecomment/([0-9]+)', DelComment),
], debug=True)
