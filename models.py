import os
import jinja2
import webapp2

from google.appengine.ext import db

# Initializes jinja templates and sets up autoescape for html
# to reduce risks of entered text
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Helper function that takes the template and parameters to render
# templates, reduces redundant code


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
# Helper function takes in value and returns encrypted version

def users_key(group='default'):
    return db.Key.from_path('users', group)
# Creates the user class in datastore and some class methods


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
# Function takes a user Id and returns a User from the datastore

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())
# Function takes a User's name and returns the User form the datastore

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
# Function takes the User input from signup and register's the new User in
# the datastore

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)
# Function calls the valid_pw function when a user sign's in to validate
# their credentials

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
# Function creates the blog key which is used as the parent to each post's key


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)
# Creates the post class and class methods.


class Post(db.Model):
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=False)
    liked = db.ListProperty(str)
# Method takes a post subject and finds the matching post

    @classmethod
    def by_subject(cls, subject):
        s = User.all().filter('subject =', subject).get()
        return s
# Method to render each blog post, takes a post object and populates post
# template

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', post=self)
# Adds comments property to Posts object

    @property
    def comments(self):
        return Comment.all().filter("post = ", str(self.key().id()))
# Creates comment class for when users add commments to a post


class Comment(db.Model):
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    post = db.StringProperty(required=True)
# Method takes a comment and renders comment template

    @classmethod
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('comment.html', post=self)
# Front page blog handler displays blog posts in th order they were created

