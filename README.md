FullStackBlog Readme
*******************

Simple Multi-User-Blog with user authoriztion, login, logout, create post and other functionality. This app was created in Python to run on Google's App Engine.


<h2>What do I need to run this?</h2>
*************************************
<ul>
<li>Multi-user blog requires goodle app engine with Python 2.
	<ul><li>Which can be found at https://cloud.google.com/appengine/downloads</li>
	<li> Python 2 can be dowloaded at https://python.org</li></ul>
</li>
<li>If you what to run the app live and display it from the appengine then it requires a google cloud account.
	<ul><li>Set up free acount https://cloud.google.com/appengine/ </li></ul>
</li>
<li><strong>***APP ID on cloud must match the app name in your local app for it to deploy successfully. You can change your app name locally in the app.yaml file.***</strong></li>

<h2>What is included?</h2>
**************************
All of the logic and handler's can be found in the main.py file. The templates directory houses the base.html, base template and each template for every page on the site. The static directory has styles.css which contains all the styling. Also included are app engine configuration, app.yaml and index.yaml. The app.yaml is important to consider when making changes to directories or adding sources. It sets the path for main.py and static/styles.css.

<h2>How do i run it? </h2>
***************************
After you have already cloned the repository, to run the blog locally you will use the app launcher sdk which was downloaded from google. First you will go to file add existing app, and add the path to FullStackBlog on your machine. 
<ul>
<li>After adding the app, you will click on the run icon. There will be an assigned port, and admin port.</li>
<li>Go to the port in a browser of your choice by typing http://localhost:8080, 
	<ul><li>note that 8080 is the standard local port</li>
	 <li>**If you have multiple apps, it may be 8081 or another port in which case you will need to adjust the address acordingly.</li>
	 </ul>
</li>
<li>The admin port is where you can view the datastore. It also contains other backend data pertaining to the app</li>
Once in the app, you will be directed to the front page of the blog, this is where the blog posts will be displayed. In order to access any functionaliy you must register with username and password. The next section goes into specifics around general functionality and default user authorizations.

<h2>What does it do?</h2>
***************************
In this app anyone can view the blog posts. New user's can access the "signup" page and register with a username and password (required) and optionally add an email. The username's are compared against the database to prevent duplicate accounts, and the passwords are encrypted and hashed using sha-256 with salt. After registering User's are prompted to personalized welcome page that displays their username. Once logged in authorized users can add new Posts, edit and delete <strong>their own</strong> blog posts.