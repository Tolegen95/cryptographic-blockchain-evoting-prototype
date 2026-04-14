from flask import Flask

import storage

app = Flask(__name__)
app.config.from_object("config.Config")
storage.initialize_storage()

from app import views
