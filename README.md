# FSND-Multi-User-Blog

## Set-Up Instructions

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
    - Parameters:
    - Description:
---
###Like Post Handler
    - Path: '/{post-id}/like'
    - Method: GET
    - Parameters:
    - Description:
---
###Unlike Post Handler
    - Path: '/{post-id}/unlike'
    - Method: GET
    - Parameters:
    - Description:
---
###Edit Comment Handler
    - Path: '/comment/{comment-id}/edit'
    - Method: GET
    - Parameters: None
    - Description: Redirects to the post page.

    - Method: POST
    - Parameters: comment-edit
    - Description: Updates comment with new text.
---
###Delete Comment Handler
    - Path: '/comment/{comment-id}/delete'
    - Method: GET
    - Parameters:
    - Description:
---
###User Hander
    - Path: 'user/{user-id}'
    - Method: GET
    - Parameters: None
    - Description: Displays avatar and posts written by the specified user.
---
###Avatars Handler
    - Path: '/avatars'
    - Method: GET
    - Parameters: None
    - Description: Displays all avatars available on the site.
---