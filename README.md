# FSND-Multi-User-Blog

FSND-Multi-User-Blog is a multi-user blog application.  Signed in users may create blog posts and comment and like other users' posts.  Certain functionality such as editing or deleting blog posts is restricted to the user who originally wrote the post.

## Language
- Python

## APIs
- NDB Datastore API

## Dependencies
- webapp2
- jinja2

## Set-Up Instructions
- Download and install the Google Cloud SDK.  This can be found at [the Google Cloud Platform site](https://cloud.google.com/appengine/docs/python/download).
- Install the gcloud component that includes the Python extension.
- Create a new Cloud Platform Console project or retrieve the project ID of an existing project from the Google Cloud Platform Console.
- Install and initialize the Google Cloud SDK.
- To run the blog app locally, open a terminal and navigate to the directory containing the app.yaml file.  Type `dev_appserver.py app.yaml` to launch the development server.  Then open a web browser and go to http://localhost:8000.
- To deploy the app, run the following command from within the directory containing the app.yaml file: `glcoud app deploy`.  Then type `gcloud app browse` to launch a browser window.

## Files Included:
- blog.py: Contains endpoints and overall logic for the site.
- app.yaml: App configuration file.
- utils.py: Contains helper functions.
- post.py: Defines the Post entity.
- user.py: Defines the User entity.
- comment.py: Defines the Comment entity.
- like.py: Defines the Like entity.

##Handlers

###Front Handler
    - Path: '/'
    - Method: GET
    - Parameters: None
    - Description: Lists all blog posts with most recent first.
---
###Login Handler
    - Path: '/login'
    - Method: GET
    - Parameters: None
    - Description: User login page.  Redirects to the front page if a user is already logged in.  Otherwise, renders login page.

    - Method: POST
    - Parameters: username, password
    - Description: Sets user cookie, then redirects to welcome page.
---
###Logout Handler
    - Path: '/logout'
    - Method: GET
    - Parameters: None
    - Description: Clears user cookie and redirects to signup page.  If no user logged in, redirects to the front page.
---
###Signup Handler
    - Path: '/signup'
    - Method: GET
    - Parameters: None
    - Description: Renders signup page.

    - Method: POST
    - Parameters: username, password, verify, email (optional)
    - Description: Checks for valid input and creates a new User.  Upon successful User creation, logs in the new user and redirects to the welcome page.
---
###Welcome Handler
    - Path: '/welcome'
    - Method: GET
    - Parameters: None
    - Description: Displays welcome message, user avatar (selected randomly), and lists posts authored by the logged in user.  If no user is logged in, redirects to the signup page.
---
###New Post Handler
    - Path: '/newpost'
    - Method: GET
    - Parameters: None
    - Description: Renders the newpost page or redirects to the login page if no user is logged in.

    - Method: POST
    - Parameters: subject, content
    - Description: Create a new Post instance and then redirects to the page for that post.
---
###Post Handler
    - Path: '/{post-id}'
    - Method: GET
    - Parameters: None
    - Description: Renders the page for this post along with comments and likes.  If no user is logged in, the comments are displayed but only logged in users may post additional comments.

    - Method: POST
    - Parameters: comment
    - Description: Creates a new Comment instance for the post.  If no user is logged in, redirects to the login page.

    - Method: DELETE
    - Parameters: None
    - Description: Deletes the selected post.  If no user is logged in, redirects to the login page.
---
###Edit Post Handler
    - Path: '/{post-id}/edit'
    - Method: GET
    - Parameters: None
    - Description: Renders the edit post page.  If no logged in user, redirects to the login page.

    - Method: POST
    - Parameters: subject, content
    - Description: Updates the subject and/or content of the post.  If no logged in user, redirects to the login page.
---
###Like Post Handler
    - Path: '/{post-id}/like'
    - Method: GET
    - Parameters: None
    - Description: Redirects to the post page.

    - Method: POST
    - Parameters: None
    - Description: Creates a new Like instance for the specified post.  If no logged in user, redirects to the login page.
---
###Unlike Post Handler
    - Path: '/{post-id}/unlike'
    - Method: GET
    - Parameters: None
    - Description: Redirects to the post page

    - Method: POST
    - Parameters: None
    - Description: Deletes the Like instace for the specified post.  If no logged in user, redirects to the login page.
---
###Comments Handler
    - Path: /{post-id}/comments
    - Method: GET
    - Parameters: None
    - Description: Lists all comments for a post.
---
###Edit Comment Handler
    - Path: '/comment/{comment-id}/edit'
    - Method: POST
    - Parameters: comment-edit
    - Description: Updates comment with new text.  If no logged in user, redirects to the login page.
---
###Delete Comment Handler
    - Path: '/comment/{comment-id}/delete'
    - Method: POST
    - Parameters: None
    - Description: Deletes specified comment.  If no logged in user, redirects to the login page.
---
###User Handler
    - Path: 'user/{user-id}'
    - Method: GET
    - Parameters: None
    - Description: Displays avatar and posts written by the specified user.
---
###Users Handler
    - Path: /users
    - Method: GET
    - Parameters: None
    - Description: Lists name and avatar of all users in the system.
---
###Avatars Handler
    - Path: '/avatars'
    - Method: GET
    - Parameters: None
    - Description: Displays all avatars available on the site.
---