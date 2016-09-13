#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import random
import hashlib
import hmac
from string import letters

import jinja2
import webapp2

from google.appengine.ext import db

# Initializes jinja templates and sets up autoescape for html
# to reduce risks of entered text
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

''' Secret helps enhance complexity of sha-256 encryption to make
 user data more secure '''
secret = '4gn-0-=x%7*@JMN-+[{78nskc83BHJH%$#_:>ngfrkvmntrf>*~HG'

# Helper function that takes the template and parameters to render
# templates, reduces redundant code


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
# Helper function takes in value and returns encrypted version


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())
# Function takes in user's password encrypts it and checkes agains
# password hash in database


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
# Main Handler that sets up basic webapp2 base functions to be inherited
# by page handlers


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params["user"] = self.user
        return render_str(template, **params)
# Render function used by handlers, reduces typing necessary to render a
# template.

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
# Sets a secure cookie using by encrypting the user_id

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
# Decrypts encrypted user_id secure cookie

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
# Set's the user's secure cookie on login

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """
        Remove secure user cookie when user logs out
        """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """
        Read and initialize secure cookie to user id for us in authentication
        """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    """
    Global function to render each blog post on the front page
    """
    response.out.write('<b>' + post.subject + '</br></br>')
    response.out.write(post.content)


def make_salt(length=5):
    """
    Creates a salt value to use to increase encryption complexity
    """
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    """
    Makes a password hash, checks if salt exists and creates password
    hash using sha-256 encryption
    """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    """
    Function hashes user password entered for login and checks
    it against hashed password in the datastore
    """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    """
    Create user key and set group to default
    """
    return db.Key.from_path('users', group)


class User(db.Model):

    """
    Creates a user class in the datastore, and creates
    class methods for accessing users by id or by name,
    also class method for user login
    """
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        """
        Function takes a user Id and returns a User from the datastore
        """
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        """
        Function takes a User's name and returns the User form the datastore
        """
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        """
        Takes the user name, pw and email from signup and registers the new
        User in the datastore
        """
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        """
        Login calls the valid_pw function when a user signs in to validate
        their credentials
        """
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
# Function creates the blog key which is used as the parent to each post's key


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):

    """
    Create Post class with class methods to get post
    by subject, to render each post using post template
    And comments property for user comments on the post
    """
    subject = db.StringProperty(required=True)
    author = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=False)
    liked = db.ListProperty(str)

    @classmethod
    def by_subject(cls, subject):
        """
        Takes a post subject and finds the matching post
        """
        s = User.all().filter('subject =', subject).get()
        return s

    def render(self):
        """
        Takes a post object and renders a given blog post. Formats spacing and
        renders the post using the post template
        """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', post=self)

    @property
    def comments(self):
        """
        Adds user comments to the post object
        """
        return Comment.all().filter("post = ", str(self.key().id()))


class Comment(db.Model):

    """
    Creates comment class for when users add comments to a post
    """
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    post = db.StringProperty(required=True)

    @classmethod
    def render(self):
        """
        Takes a comment object and renders the comment using the
        comment template
        """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('comment.html', post=self)
# Front page blog handler displays blog posts in th order they were created


class BlogFront(Handler):

    """
    Front blog page handler, queries datastore for the posts and displays them
    in order they were created
    """

    def get(self):
        posts = Post.all().order('-created')
        # posts = db.GqlQuery
        # ("select * from Post order by created desc limit 10")
        self.render('front.html', posts=posts)


class PostPage(Handler):

    """
    Post page handler takes post_id from the url and renders the post
    """

    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render('permalink.html', post=post)
# Handler for creating new post gets newpost form


class NewPost(Handler):

    """
    Page handler for making new blog post; get method checks that user is
    logged in; renders the newpost template. Post method takes the subject,
    content and author data from the newpost form and puts it to the database
    as a new post.
    """

    def get(self):
        if self.user:
            self.render('newpost.html')
        else:
            self.redirect('/login')
# Post method takes new post data from entry form and puts into datastore

    def post(self):
        if self.user:
            subject = self.request.get("subject")
            content = self.request.get("content")
            author = self.request.get("author")
# Check that user entered subject and content for the post
            if subject and content:
                post = Post(
                    parent=blog_key(),
                    subject=subject,
                    author=author,
                    content=content,
                    likes=0)
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
# Returns an error if user forgets to enter a subject or content for the
# blog post.
            else:
                error = "Please enter subject and content please!"
                self.render(
                    'newpost.html',
                    subject=subject,
                    author=author,
                    content=content,
                    error=error)
        else:
            self.redirect('/login')
# Handler for users to edit existing blog posts. Gets the post information
# and populates editpost template


class EditPost(Handler):

    """
    Handler for users to edit existing blog posts. Get method, querries the
    post information from the datastore and populates the editpost template.
    Also runs check to make sure that user is logged in and redirects to the
    login page if they are not.
    """

    def get(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
# Check if user name matches the author so that users can only edit their
# own posts
            if self.user.name == post.author:
                self.render(
                    'editpost.html',
                    subject=post.subject,
                    content=post.content,
                    post_id=post_id)
# Returns an error if user tries to edit a post that they did not write
            else:
                error = "This is not your post"
                self.write(error)
# If user is not registered user, redirect to login page
        else:
            self.redirect('/login')

    def post(self):
        """
        Checks that user is logged in and get the changes from the edit post
        form and updates the entry in the datastore. Subject is the blog post
        subject from the editpost form, the content is the post content from
        the form. The username is in a secure cookie in the browser and has to
        match the authors name from the datastore.
        """
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            subject = self.request.get('subject')
            content = self.request.get('content')
# Check that post is not blank, and put post
            if subject and content and self.user.name == post.author:
                post.subject = subject
                post.content = content
                post.put()
                self.redirect('/blog/%s' % str(post.key().id()))
# If the post is missing a subject or content will return an error message
# and re generate edit page
            else:
                error = "Please enter both subject and content!"
                self.render('newpost.html',
                            subject=subject,
                            content=content,
                            error=error)
# If user is not logged in registered user, redirect to login page
        else:
            self.redirect('/login')


class DeletePost(Handler):

    """
    DeletePost handles user deletes of existing blog posts. Get method gets
    blog post id from the url and gets the Post object from the datastore.
    Check user name against author name to make sure that they match and then
    render the delete post template. If user submits confirm delete, post
    method verifies authorization and deletes entry from datastore.
    """

    def get(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
# Checks that user name matches the author name and renders delete page to
# confirm post deletion.
            if self.user.name == post.author:
                self.render('deletepost.html', post=post)
# If username doesn't match author return to the front blog page
            else:
                self.redirect("/blog")
# If user is not logged in registered user redirect to login page
        else:
            self.redirect('/login')
# Post method deletes post from the database when user confirms delete.

    def post(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
# Checks that username matches author's name for the post and deletes it
# from the datastore and renders delete success page
            if post and post.author == self.user.name:
                post.delete()
                self.render('deletesuccess.html')
# If user's name doesn't match author's name will not delete post and
# return to front blog page
            else:
                self.redirect('/blog')
# if user is not a registered user, redirect to login page
        else:
            self.redirect('/login')


class AddComment(Handler):

    """
    Handles user comments on blog posts. Get method gets post object and
    renders the new comment page. Subject, content and post_id are
    atributes of the post object retrieved from the datastore. Post method
    verifies user login and puts the new comment to the datastore.
    """

    def get(self):
        if self.user:
            post_id = self.request.get("post")
            post = Post.get_by_id(int(post_id), parent=blog_key())
            subject = post.subject
            content = post.content
            self.render(
                'newcomment.html',
                subject=subject,
                content=content,
                post=post_id)
# If not signed in as registered user, returns to signup form
        else:
            self.redirect('/login')
# Post method, takes the comment data and check usere data puts comment to
# the datastore.

    def post(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            content = self.request.get("comment")
            author = self.request.get("author")
            subject = self.request.get("subject")
# Checks that comment is not blank and puts comment data to database
            if content:
                comment = Comment(parent=self.user.key(),
                                  post=post_id,
                                  author=author,
                                  content=content)
                comment.put()
                self.redirect('/blog/%s' % str(post_id))
# If comment is blank returns an error and re renders new comment page
            else:
                error = "Please leave a comment or return to the blog page"
                self.render(
                    'newcomment.html',
                    subject=subject,
                    content=content,
                    post=post_id,
                    error=error)
# If user is not a registered user redirects to signup page.
        else:
            self.redirect('/login')
# Handler for user to edit their own existing comment


class EditComment(Handler):

    """
    Handler for editing user comments in the datastore. Get method gets
    the comment from the datastore and verifies that user is the author
    and populates the edit comment form with the comment data for the user to
    edit. Post method verifies that user matches author and updates the
    comment to the datastore
    """

    def get(self):
        if self.user:
            comment_id = self.request.get("comment")
            cKey = db.Key.from_path(
                "Comment", int(comment_id), parent=self.user.key())
            comment = db.get(cKey)
            post_id = self.request.get("post")
            pKey = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(pKey)
# Checks that comment exists and the user's name matches the comment
# author's name
            if comment and self.user.name == comment.author:
                self.render('editcomment.html',
                            subject=post.subject,
                            content=post.content,
                            commentContent=comment.content)
# Returns an error and renders new comment page if user tries to edit a
# comment they didn't write
            else:
                error = "This is not your post enter your own comment or edit"
                error += " one of your own"
                self.render('newcomment.html', post_id=post_id, error=error)
# If user is not registered user returns login page
        else:
            self.redirect('/login')
# Post method checks user data and takes edited comment data and puts the
# changes to the datastore

    def post(self):
        if self.user:
            comment_id = self.request.get("comment")
            key = db.Key.from_path(
                "Comment", int(comment_id), parent=self.user.key())
            comment = db.get(key)
            content = self.request.get("commentContent")
# Check that comment isn't blank and user's name matches the comment
# author's name the put edited comment to the datastore.
            if content and self.user.name == comment.author:
                comment.content = content
                comment.put()
                self.redirect('/blog')
# If comment is blank returns an error and render's the edit comment page
            else:
                error = "Comment must contain content please try again"
                self.render('editcomment.html',
                            subject=post.subject,
                            content=post.content,
                            comment=comment.content)
# If user is not a registerd user redirects to login page
        else:
            self.redirect('/login')


class DeleteComment(Handler):

    """
    Handler for deleting existing comments from blog posts. Get method
    verify that user is the author of the comment and gets the comment from
    the datastore. Post method verify that user is author and delete the
    comment entry from the datastore.
    """

    def get(self):
        if self.user:
            comment_id = self.request.get("comment")
            cKey = db.Key.from_path(
                "Comment", int(comment_id), parent=self.user.key())
            comment = db.get(cKey)
            post_id = self.request.get("post")
            pKey = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(pKey)
# Check that comment exists and that user's name matches the comment
# author's name
            if comment and self.user.name == comment.author:
                self.render('deletecomment.html',
                            subject=post.subject,
                            content=post.content,
                            comment=comment.content)
# If user name doesn't match author's name or comment doesn't exist
# redirects to the front blog page
            else:
                self.redirect('/blog')
# If user is not registered user, redirect to the login page.
        else:
            self.redirect('/login')
# Post method, checks user data and deletes the comment from the datastore.

    def post(self):
        if self.user:
            comment_id = self.request.get("comment")
            key = db.Key.from_path(
                "Comment", int(comment_id), parent=self.user.key())
            comment = db.get(key)
# Check that comment exists and that the author's name matches the user's name
            if comment and comment.author == self.user.name:
                comment.delete()
                self.render('deletesuccess.html')
# If comment doesn't exist or user doesn't match author return the front
# blog page.
            else:
                self.redirect('/blog')
# If user is not registered user redirect to the login page
        else:
            self.redirect('/login')


class LikePost(Handler):

    """
    Checks the user credentials and handles post likes. Each user can only
    like a post submitted by a different user and can only like each blog
    post one time.
    """

    def get(self):
        if self.user:
            post_id = self.request.get("post")
            key = db.Key.from_path("Post", int(post_id), parent=blog_key())
            post = db.get(key)
            author = post.author
            username = self.user.name
# Checks if user is not author and if user has already liked the post yet
            if author == username or username in post.liked:
                self.redirect('/blog')
# If user hasn't written or liked post then puts 1 more like and username
# is added to the post's liked list
            else:
                post.likes += 1
                post.liked.append(username)
                post.put()
                self.redirect('/blog')
# If user is not signed in then returns to login page
        else:
            self.redirect('/login')
# Handler generates personalized message to welcome new user to the blog
# and confirm registration success


class Welcome(Handler):

    """
    Welcome handler follows the regsitration page, and generates a
    personalized message to welcome the new user to the blog, confriming
    successful registration.
    """

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
# If signup didn't work or user logged out, then returns to signup page
        else:
            self.redirect('/signup')
# Function validates that Username is contains letters or numbers and is
# 3-20 characters in length
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)
# Function validates that the password is 3-20 characters in length
PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)
# Validates that email is in the correct format
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)
# Handler for new user to signup with a unique username, matching
# passwords and valid email (optional)


class Signup(Handler):

    """
    Handler renders registration form for new user to signup to blog, checks
    that username is unique, and passwords entry match, email submission is
    optional. If user enters incorrect data and the signup will re-render. If
    the user data is valid, post method with put the user to the database and
    render the welcome page.
    """

    def get(self):
        self.render("signup.html")
# Takes user input and validates username is unique and that username,
# password, and email entereed are valid

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
# Creates dictionary for validating users entered username and email
        params = dict(username=self.username, email=self.email)
# Takes user entered username, and checks if its valid using
# valid_username function
        if not valid_username(self.username):
            params['error_username'] = "That is not a valid username."
            have_error = True
# Takes user entered password, and passes it to valid_password function
# returns error message if invalid
        if not valid_password(self.password):
            params['error_password'] = "That is not a valid password"
            have_error = True
# Checks that user's two entered passwords match and returns an errror if
# they don't
        elif self.password != self.verify:
            params['error_verify'] = "Oops your passwords didn't match."
            have_error = True
# Takes entered email and passes it to valid_email to check if it is a
# valid email
        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email address"
# If there is an error, will re render the signup form with any valid user
# data and the appropriate error message(s)
        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()
# Method finishes validation, and returns error if not properly overwriten
# with register handler.

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):

    """
    Overwrites the done function from signup class, checks that the user is
    unique and puts the user entry to the datastore.
    """

    def done(self):
        # Checks if entered user name matches an already existing user's name.
        u = User.by_name(self.username)
# Returns an error message if user name already exists in the database
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username=msg)
# User name is not found in the database, puts new user's data to datastore
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
# Logs in the newly registered user and redirects to the personalized
# welcome page
            self.login(u)
            self.redirect('/welcome')


class Login(Handler):

    """
    Handles user login, checks the user's name and password hash against the
    datastore and stores the user's id in a secure cookie.
    """

    def get(self):
        self.render('login.html')
# Takes user's credentials and stores them in variables to check against
# datastore

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
# Passes user's credentials to the login function
        u = User.login(username, password)
# If credentials match, log user in and redirect to front blog page
        if u:
            self.login(u)
            self.redirect('/blog')
# If credentials do not match datastore entry return error message and
# redirect to login page.
        else:
            msg = 'Invalid login'
            self.render('login.html', error=msg)


class Logout(Handler):

    """
    Handles logout, passes user into logout function, which logs the user out
    and deletes the secure cookie
    """

    def get(self):
        self.logout()
        self.redirect('/signup')

# Asigns handlers to their respescitve url address
app = webapp2.WSGIApplication([
    ('/', BlogFront),
    ('/blog/?', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/newpost', NewPost),
    ('/welcome', Welcome),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/editpost/?', EditPost),
    ('/deletepost/?', DeletePost),
    ('/addcomment/?', AddComment),
    ('/editcomment/?', EditComment),
    ('/deletecomment/?', DeleteComment),
    ('/like/?', LikePost)
], debug=True)
