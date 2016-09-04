FullStackBlog Readme
*******************

Simple Multi-User-Blog with user authoriztion, login, logout, create post and other functionality. This app was created in Python to run on Google's App Engine.


<h2>What do I need to run this?</h2>
*************************************
Multi-user blog requires goodle app engine with Python 2. If you what to run the app live and broadcast it to the appengine then it requires a google cloud account. <strong>APP ID on cloud must match the app name in your local app for it to deploy successfully. You can change your app name locally in the app.yaml file.</strong>

<h2>What is included?</h2>
**************************
All of the logic and handler's can be found in the main.py file. The templates directory houses the base.html, base template and each template for every page on the site. The static directory has styles.css which contains all the styling. Also included are app engine configuration, app.yaml and index.yaml. The app.yaml is important to consider when making changes to directories or adding sources. It sets the path for main.py and static/styles.css.

<h2>What does it do?</h2>
***************************
In this app anyone can view the blog posts. New user's can access the "signup" page and register with a username and password (required) and optionally add an email. The username's are compared against the database to prevent duplicate accounts, and the passwords are encrypted and hashed using sha-256 with salt. After registering User's are prompted to personalized welcome page that displays their username. Once logged in authorized users can add new Posts, edit and delete <strong>their own</strong> blog posts.