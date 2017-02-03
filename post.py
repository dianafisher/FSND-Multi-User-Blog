
from google.appengine.ext import db

class Post(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        # replace new line characters with breaks
        self.__render_text = self.content.replace('\n', '<br>')
        return render('post.html', post = self)